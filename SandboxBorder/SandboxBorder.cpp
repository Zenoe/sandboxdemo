// ============================================================
//  SandboxBorder.cpp  —  Injected shell-broker payload
//
//  Window borders and title prefixes are owned by the Qt host. This DLL
//  only redirects "Show in folder" requests to the host broker so Explorer
//  can be launched inside the same sandbox box.
// ============================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define SANDBOXBORDER_EXPORTS
#include "SandboxBorder.h"
#include <shlobj.h>
#include <shellapi.h>
#include <string>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "Shell32.lib")

static wchar_t g_BoxName[64] = {};
static wchar_t g_HookMode[16] = SANDBOX_HOOK_MODE_INLINE;
static constexpr wchar_t g_PipeName[] = SANDBOX_PIPE_NAME;

using PFN_SHOpenFolderAndSelectItems = HRESULT(WINAPI*)(
    PCIDLIST_ABSOLUTE, UINT, PCUITEMID_CHILD_ARRAY, DWORD);
using PFN_ShellExecuteW = HINSTANCE(WINAPI*)(
    HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);

static PFN_SHOpenFolderAndSelectItems g_origSHOpen = nullptr;
static PFN_ShellExecuteW g_origShellExecuteW = nullptr;

enum class HookMode {
    Inline,
    Iat
};

static HookMode g_ActiveHookMode = HookMode::Inline;
static SRWLOCK g_InlineHookLock = SRWLOCK_INIT;

struct InlineHook {
    void* target = nullptr;
    void* replacement = nullptr;
    BYTE original[12] = {};
    SIZE_T size = sizeof(original);
    bool installed = false;
};

static InlineHook g_SHOpenInlineHook;
static InlineHook g_ShellExecuteInlineHook;

static void NotifyHostOpenFolder(const wchar_t* realPath)
{
    HANDLE hPipe = CreateFileW(g_PipeName, GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, 0, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE)
        return;

    char boxUtf8[64] = {};
    char pathUtf8[MAX_PATH * 2] = {};
    WideCharToMultiByte(CP_UTF8, 0, g_BoxName, -1,
        boxUtf8, sizeof(boxUtf8), nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, realPath, -1,
        pathUtf8, sizeof(pathUtf8), nullptr, nullptr);

    std::string escapedPath;
    for (char ch : std::string(pathUtf8))
        escapedPath += ch == '\\' ? "\\\\" : std::string(1, ch);

    char message[1024];
    int length = _snprintf_s(message, sizeof(message), _TRUNCATE,
        "{\"cmd\":\"openFolder\",\"box\":\"%s\",\"path\":\"%s\"}\n",
        boxUtf8, escapedPath.c_str());

    if (length > 0) {
        DWORD written = 0;
        WriteFile(hPipe, message, static_cast<DWORD>(length), &written, nullptr);
    }
    CloseHandle(hPipe);
}

static bool PatchIAT(HMODULE module, const char* dll, const char* function,
    PROC replacement, PROC* original)
{
    if (!module)
        return false;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<BYTE*>(module) + dos->e_lfanew);
    auto& importDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir.VirtualAddress)
        return false;

    auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        reinterpret_cast<BYTE*>(module) + importDir.VirtualAddress);
    for (; descriptor->Name; ++descriptor) {
        auto* importedDll = reinterpret_cast<char*>(
            reinterpret_cast<BYTE*>(module) + descriptor->Name);
        if (_stricmp(importedDll, dll) != 0)
            continue;

        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
            reinterpret_cast<BYTE*>(module) + descriptor->FirstThunk);
        auto* originalThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
            reinterpret_cast<BYTE*>(module) + descriptor->OriginalFirstThunk);

        for (; originalThunk->u1.AddressOfData; ++thunk, ++originalThunk) {
            if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal))
                continue;

            auto* import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                reinterpret_cast<BYTE*>(module) +
                originalThunk->u1.AddressOfData);
            if (_stricmp(reinterpret_cast<char*>(import->Name), function) != 0)
                continue;

            DWORD oldProtection = 0;
            if (!VirtualProtect(&thunk->u1.Function, sizeof(PROC),
                PAGE_READWRITE, &oldProtection)) {
                return false;
            }
            if (original)
                *original = reinterpret_cast<PROC>(thunk->u1.Function);
            thunk->u1.Function = reinterpret_cast<ULONG_PTR>(replacement);
            VirtualProtect(&thunk->u1.Function, sizeof(PROC),
                oldProtection, &oldProtection);
            return true;
        }
    }
    return false;
}

static bool InstallInlineHook(InlineHook& hook, void* target, void* replacement)
{
#if defined(_M_X64) || defined(__x86_64__)
    if (!target || !replacement)
        return false;

    hook.target = target;
    hook.replacement = replacement;
    std::memcpy(hook.original, target, hook.size);

    BYTE patch[12] = {
        0x48, 0xB8,                         // mov rax, imm64
        0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xE0                          // jmp rax
    };
    *reinterpret_cast<UINT64*>(patch + 2) =
        reinterpret_cast<UINT64>(replacement);

    DWORD oldProtection = 0;
    if (!VirtualProtect(target, hook.size, PAGE_EXECUTE_READWRITE,
        &oldProtection)) {
        return false;
    }

    std::memcpy(target, patch, sizeof(patch));
    FlushInstructionCache(GetCurrentProcess(), target, hook.size);
    VirtualProtect(target, hook.size, oldProtection, &oldProtection);
    hook.installed = true;
    return true;
#else
    UNREFERENCED_PARAMETER(hook);
    UNREFERENCED_PARAMETER(target);
    UNREFERENCED_PARAMETER(replacement);
    return false;
#endif
}

static void RestoreInlineHook(InlineHook& hook)
{
    if (!hook.installed || !hook.target)
        return;

    DWORD oldProtection = 0;
    if (!VirtualProtect(hook.target, hook.size, PAGE_EXECUTE_READWRITE,
        &oldProtection)) {
        return;
    }

    std::memcpy(hook.target, hook.original, hook.size);
    FlushInstructionCache(GetCurrentProcess(), hook.target, hook.size);
    VirtualProtect(hook.target, hook.size, oldProtection, &oldProtection);
    hook.installed = false;
}

static void ReinstallInlineHook(InlineHook& hook)
{
    if (!hook.target || !hook.replacement || hook.installed)
        return;

#if defined(_M_X64) || defined(__x86_64__)
    BYTE patch[12] = {
        0x48, 0xB8,
        0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xE0
    };
    *reinterpret_cast<UINT64*>(patch + 2) =
        reinterpret_cast<UINT64>(hook.replacement);

    DWORD oldProtection = 0;
    if (!VirtualProtect(hook.target, hook.size, PAGE_EXECUTE_READWRITE,
        &oldProtection)) {
        return;
    }

    std::memcpy(hook.target, patch, sizeof(patch));
    FlushInstructionCache(GetCurrentProcess(), hook.target, hook.size);
    VirtualProtect(hook.target, hook.size, oldProtection, &oldProtection);
    hook.installed = true;
#endif
}

static HRESULT CallOriginalSHOpen(
    PCIDLIST_ABSOLUTE pidl, UINT count,
    PCUITEMID_CHILD_ARRAY children, DWORD flags)
{
    if (g_ActiveHookMode != HookMode::Inline) {
        return g_origSHOpen
            ? g_origSHOpen(pidl, count, children, flags)
            : E_FAIL;
    }

    AcquireSRWLockExclusive(&g_InlineHookLock);
    RestoreInlineHook(g_SHOpenInlineHook);
    ReleaseSRWLockExclusive(&g_InlineHookLock);

    auto original = reinterpret_cast<PFN_SHOpenFolderAndSelectItems>(
        g_SHOpenInlineHook.target);
    HRESULT result = original
        ? original(pidl, count, children, flags)
        : E_FAIL;

    AcquireSRWLockExclusive(&g_InlineHookLock);
    ReinstallInlineHook(g_SHOpenInlineHook);
    ReleaseSRWLockExclusive(&g_InlineHookLock);
    return result;
}

static HINSTANCE CallOriginalShellExecuteW(
    HWND window, LPCWSTR operation, LPCWSTR file, LPCWSTR parameters,
    LPCWSTR directory, INT showCommand)
{
    if (g_ActiveHookMode != HookMode::Inline) {
        return g_origShellExecuteW
            ? g_origShellExecuteW(window, operation, file, parameters,
                directory, showCommand)
            : reinterpret_cast<HINSTANCE>(static_cast<INT_PTR>(2));
    }

    AcquireSRWLockExclusive(&g_InlineHookLock);
    RestoreInlineHook(g_ShellExecuteInlineHook);
    ReleaseSRWLockExclusive(&g_InlineHookLock);

    auto original = reinterpret_cast<PFN_ShellExecuteW>(
        g_ShellExecuteInlineHook.target);
    HINSTANCE result = original
        ? original(window, operation, file, parameters, directory, showCommand)
        : reinterpret_cast<HINSTANCE>(static_cast<INT_PTR>(2));

    AcquireSRWLockExclusive(&g_InlineHookLock);
    ReinstallInlineHook(g_ShellExecuteInlineHook);
    ReleaseSRWLockExclusive(&g_InlineHookLock);
    return result;
}

static HRESULT WINAPI Hook_SHOpenFolderAndSelectItems(
    PCIDLIST_ABSOLUTE pidl, UINT count,
    PCUITEMID_CHILD_ARRAY children, DWORD flags)
{
    wchar_t path[MAX_PATH] = {};
    if (SHGetPathFromIDListW(pidl, path)) {
        NotifyHostOpenFolder(path);
        return S_OK;
    }
    return CallOriginalSHOpen(pidl, count, children, flags);
}

static HINSTANCE WINAPI Hook_ShellExecuteW(
    HWND window, LPCWSTR operation, LPCWSTR file, LPCWSTR parameters,
    LPCWSTR directory, INT showCommand)
{
    bool isOpen = !operation || !_wcsicmp(operation, L"open") ||
        !_wcsicmp(operation, L"explore");
    if (isOpen && file) {
        DWORD attributes = GetFileAttributesW(file);
        if (attributes != INVALID_FILE_ATTRIBUTES &&
            (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            NotifyHostOpenFolder(file);
            return reinterpret_cast<HINSTANCE>(static_cast<INT_PTR>(42));
        }
    }

    return CallOriginalShellExecuteW(window, operation, file, parameters,
        directory, showCommand);
}

extern "C" SBAPI BOOL WINAPI SandboxBorder_Init(void)
{
    GetEnvironmentVariableW(SANDBOX_BORDER_BOX_ENV,
        g_BoxName, ARRAYSIZE(g_BoxName));
    GetEnvironmentVariableW(SANDBOX_HOOK_MODE_ENV,
        g_HookMode, ARRAYSIZE(g_HookMode));
    if (g_BoxName[0] == L'\0')
        return FALSE;

    HMODULE executable = GetModuleHandleW(nullptr);
    HMODULE shell = GetModuleHandleW(L"shell32.dll");

    if (_wcsicmp(g_HookMode, SANDBOX_HOOK_MODE_IAT) == 0) {
        g_ActiveHookMode = HookMode::Iat;
        PatchIAT(executable, "shell32.dll", "SHOpenFolderAndSelectItems",
            reinterpret_cast<PROC>(Hook_SHOpenFolderAndSelectItems),
            reinterpret_cast<PROC*>(&g_origSHOpen));
        PatchIAT(executable, "shell32.dll", "ShellExecuteW",
            reinterpret_cast<PROC>(Hook_ShellExecuteW),
            reinterpret_cast<PROC*>(&g_origShellExecuteW));

        if (!g_origSHOpen && shell) {
            g_origSHOpen = reinterpret_cast<PFN_SHOpenFolderAndSelectItems>(
                GetProcAddress(shell, "SHOpenFolderAndSelectItems"));
        }
        if (!g_origShellExecuteW && shell) {
            g_origShellExecuteW = reinterpret_cast<PFN_ShellExecuteW>(
                GetProcAddress(shell, "ShellExecuteW"));
        }
    }
    else {
        g_ActiveHookMode = HookMode::Inline;
        if (!shell)
            return FALSE;

        void* shOpen = reinterpret_cast<void*>(
            GetProcAddress(shell, "SHOpenFolderAndSelectItems"));
        void* shellExecute = reinterpret_cast<void*>(
            GetProcAddress(shell, "ShellExecuteW"));

        bool shOpenOk = InstallInlineHook(g_SHOpenInlineHook, shOpen,
            reinterpret_cast<void*>(Hook_SHOpenFolderAndSelectItems));
        bool shellExecuteOk = InstallInlineHook(g_ShellExecuteInlineHook,
            shellExecute, reinterpret_cast<void*>(Hook_ShellExecuteW));
        if (!shOpenOk && !shellExecuteOk)
            return FALSE;
    }
    return TRUE;
}

extern "C" SBAPI BOOL WINAPI SandboxBorder_Uninit(void)
{
    AcquireSRWLockExclusive(&g_InlineHookLock);
    RestoreInlineHook(g_SHOpenInlineHook);
    RestoreInlineHook(g_ShellExecuteInlineHook);
    ReleaseSRWLockExclusive(&g_InlineHookLock);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
    }
    else if (reason == DLL_PROCESS_DETACH && reserved == nullptr) {
        SandboxBorder_Uninit();
    }
    return TRUE;
}
