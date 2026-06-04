// ============================================================
//  SandboxBorder.cpp  —  Injected DLL payload  v4
//
//  Build:
//    cl /LD /O2 /W4 /DSANDBOXBORDER_EXPORTS SandboxBorder.cpp
//       /link /OUT:SandboxBorder.dll User32.lib Shell32.lib Comctl32.lib
//
//  KEY DESIGN DECISIONS (v4)
//  ──────────────────────────────────────────────────────────
//
//  BUG 1 FIX — DLL was loading into normal (unsandboxed) processes:
//    SetWindowsHookExW(WH_CBT, proc, hModule, tid) with hModule!=NULL
//    is a GLOBAL hook even with a specific tid.  Windows injects the
//    DLL into every process whose thread matches the tid — which on a
//    desktop means ALL processes that create windows.
//    FIX: always pass hModule=NULL.  In-process hooks (NULL module)
//    are private to the process that calls SetWindowsHookEx.
//    The ThreadWatcher is removed entirely — for Notepad/Explorer one
//    thread is sufficient.  For Chrome, the DLL is injected into each
//    child process separately by the launcher (each child gets its own
//    context-hijack stub).
//
//  BUG 2 FIX — DWM erased the border drawn in WM_NCPAINT:
//    On Windows 10/11 DWM composites the NC area asynchronously.
//    Drawing into GetWindowDC during WM_NCPAINT is overwritten the
//    next time DWM flushes its back-buffer to screen (~16 ms).
//    FIX: Create a transparent layered COMPANION WINDOW — a borderless
//    WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST child of the
//    desktop that exactly covers the target window and paints only the
//    yellow frame.  Because it is TOPMOST and transparent to input
//    (WS_EX_TRANSPARENT), it always appears above DWM's output and
//    never interferes with mouse clicks.  A WinEventHook on
//    EVENT_OBJECT_LOCATIONCHANGE keeps it repositioned as the target
//    moves or resizes.  This is exactly what Sandboxie does internally.
//
//  COMPANION WINDOW APPROACH
//  ─────────────────────────
//  For each sandboxed top-level HWND we create one companion:
//    Style:    WS_POPUP (no caption, no border)
//    ExStyle:  WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST
//              | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW
//    Size:     same RECT as the target (GetWindowRect)
//    Parent:   HWND_DESKTOP (nullptr)
//    Content:  painted yellow only on a BORDER_THICKNESS-pixel frame;
//              interior is fully transparent via SetLayeredWindowAttributes
//              with LWA_COLORKEY (magenta = transparent color key).
//
//  The companion's WM_PAINT draws:
//    - Fill entire client with magenta (transparent key color)
//    - Draw the four border strips in yellow on top
//  SetLayeredWindowAttributes(hwnd, MAGENTA, 0, LWA_COLORKEY) makes
//  magenta pixels fully transparent while yellow pixels are opaque.
//
//  WinEventHook (SetWinEventHook, in-process) fires on:
//    EVENT_OBJECT_LOCATIONCHANGE  → reposition companion
//    EVENT_OBJECT_DESTROY         → destroy companion
//    EVENT_OBJECT_SHOW            → show companion
//    EVENT_OBJECT_HIDE            → hide companion
// ============================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define SANDBOXBORDER_EXPORTS
#include "SandboxBorder.h"
#include <shlobj.h>
#include <shellapi.h>
#include <strsafe.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>
#include <cstdio>

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Comctl32.lib")

// ============================================================
//  Constants
// ============================================================
static constexpr COLORREF TRANSPARENT_KEY = RGB(255, 0, 255); // magenta
static constexpr int      T = SANDBOX_BORDER_THICKNESS;
static constexpr wchar_t  COMPANION_CLASS[] = L"SbxBorderCompanion";

// ============================================================
//  Globals
// ============================================================
static HINSTANCE g_hModule           = nullptr;
static wchar_t   g_BoxName[64]       = {};
static wchar_t   g_SandboxRoot[MAX_PATH] = {};
static constexpr wchar_t g_PipeName[] = SANDBOX_PIPE_NAME;

// Per-target companion tracking
struct CompanionEntry {
    HWND    target;        // the sandboxed app window
    HWND    companion;     // our overlay window
    WNDPROC originalProc;  // target WndProc before our subclass
    bool    hoverTitle;
    bool    moving;
    bool    trackingLeave;
};
static std::recursive_mutex     g_compMutex;
static std::vector<CompanionEntry> g_companions;

// WinEventHook handle
static HWINEVENTHOOK g_winEventHook = nullptr;

// CBT hook (in-process, current thread only)
static HHOOK g_cbtHook = nullptr;

static LRESULT CALLBACK TargetWndProc(HWND hWnd, UINT msg,
                                       WPARAM wParam, LPARAM lParam);

// ============================================================
//  FindCompanion / RemoveCompanion
// ============================================================
static HWND FindCompanion(HWND target)
{
    std::lock_guard<std::recursive_mutex> lk(g_compMutex);
    for (auto& e : g_companions)
        if (e.target == target) return e.companion;
    return nullptr;
}

static CompanionEntry* FindCompanionEntryLocked(HWND target)
{
    for (auto& e : g_companions)
        if (e.target == target) return &e;
    return nullptr;
}

static void RemoveCompanion(HWND target)
{
    std::lock_guard<std::recursive_mutex> lk(g_compMutex);
    for (auto it = g_companions.begin(); it != g_companions.end(); ++it) {
        if (it->target != target)
            continue;

        if (IsWindow(it->target) && it->originalProc) {
            SetWindowLongPtrW(it->target, GWLP_WNDPROC,
                reinterpret_cast<LONG_PTR>(it->originalProc));
        }
        g_companions.erase(it);
        return;
    }
}

static bool IsCaptionHit(LRESULT hit)
{
    return hit == HTCAPTION || hit == HTSYSMENU || hit == HTMINBUTTON ||
        hit == HTMAXBUTTON || hit == HTCLOSE || hit == HTHELP;
}

// ============================================================
//  RepositionCompanion — sync overlay RECT to target window
// ============================================================
static void RepositionCompanion(HWND companion, HWND target, bool show)
{
    if (!IsWindow(target) || !IsWindow(companion)) return;

    RECT rc{};
    GetWindowRect(target, &rc);
    int x = rc.left, y = rc.top;
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;

    if (!show || IsIconic(target) || !IsWindowVisible(target)) {
        ShowWindow(companion, SW_HIDE);
        return;
    }

    // Place companion exactly over the target, above everything
    SetWindowPos(companion, HWND_TOPMOST, x, y, w, h,
                 SWP_NOACTIVATE | SWP_SHOWWINDOW);
}

static void RepositionCompanionToRect(HWND companion, const RECT& rc, bool show)
{
    if (!IsWindow(companion)) return;
    if (!show) {
        ShowWindow(companion, SW_HIDE);
        return;
    }

    SetWindowPos(companion, HWND_TOPMOST,
                 rc.left, rc.top,
                 rc.right - rc.left, rc.bottom - rc.top,
                 SWP_NOACTIVATE | SWP_SHOWWINDOW);
}

static void SyncCompanion(CompanionEntry& entry)
{
    RepositionCompanion(entry.companion, entry.target,
        entry.hoverTitle || entry.moving);
}

// ============================================================
//  Companion WndProc
// ============================================================
static LRESULT CALLBACK CompanionWndProc(HWND hWnd, UINT msg,
                                          WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_PAINT:
    {
        PAINTSTRUCT ps{};
        HDC hdc = BeginPaint(hWnd, &ps);

        RECT rc{};
        GetClientRect(hWnd, &rc);
        int w = rc.right;
        int h = rc.bottom;

        // Fill entire window with the transparent key color
        HBRUSH hMagenta = CreateSolidBrush(TRANSPARENT_KEY);
        FillRect(hdc, &rc, hMagenta);
        DeleteObject(hMagenta);

        // Draw yellow border strips on top
        if (w > 0 && h > 0) {
            HBRUSH hYellow = CreateSolidBrush(SANDBOX_BORDER_COLOR);
            RECT rTop    = { 0,   0,   w,   T   };
            RECT rBottom = { 0,   h-T, w,   h   };
            RECT rLeft   = { 0,   T,   T,   h-T };
            RECT rRight  = { w-T, T,   w,   h-T };
            FillRect(hdc, &rTop,    hYellow);
            FillRect(hdc, &rBottom, hYellow);
            FillRect(hdc, &rLeft,   hYellow);
            FillRect(hdc, &rRight,  hYellow);
            DeleteObject(hYellow);
        }

        EndPaint(hWnd, &ps);
        return 0;
    }

    case WM_ERASEBKGND:
        return 1; // prevent flicker — WM_PAINT handles background

    case WM_NCHITTEST:
        // Make the entire companion transparent to mouse input
        return HTTRANSPARENT;

    default:
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
}

// ============================================================
//  CreateCompanion — create the overlay window for a target HWND
// ============================================================
static HWND CreateCompanion(HWND target)
{
    if (HWND existing = FindCompanion(target))
        return existing;

    RECT rc{};
    GetWindowRect(target, &rc);

    HWND companion = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST |
        WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
        COMPANION_CLASS,
        nullptr,              // no title
        WS_POPUP,             // no NC area at all
        rc.left, rc.top,
        rc.right - rc.left, rc.bottom - rc.top,
        nullptr,              // no parent — desktop child
        nullptr, g_hModule, nullptr);

    if (!companion) return nullptr;

    // Magenta = transparent, yellow = opaque
    SetLayeredWindowAttributes(companion, TRANSPARENT_KEY, 0, LWA_COLORKEY);

    ShowWindow(companion, SW_HIDE);

    WNDPROC original = reinterpret_cast<WNDPROC>(
        GetWindowLongPtrW(target, GWLP_WNDPROC));
    {
        std::lock_guard<std::recursive_mutex> lk(g_compMutex);
        g_companions.push_back({ target, companion, original, false, false, false });
    }

    if (!SetWindowLongPtrW(target, GWLP_WNDPROC,
        reinterpret_cast<LONG_PTR>(TargetWndProc))) {
        DestroyWindow(companion);
        RemoveCompanion(target);
        return nullptr;
    }

    return companion;
}

static LRESULT CALLBACK TargetWndProc(HWND hWnd, UINT msg,
                                       WPARAM wParam, LPARAM lParam)
{
    WNDPROC original = nullptr;
    {
        std::lock_guard<std::recursive_mutex> lk(g_compMutex);
        if (auto* entry = FindCompanionEntryLocked(hWnd)) {
            original = entry->originalProc;

            switch (msg) {
            case WM_NCMOUSEMOVE:
                if (IsCaptionHit((LRESULT)wParam)) {
                    entry->hoverTitle = true;
                    if (!entry->trackingLeave) {
                        TRACKMOUSEEVENT tme{};
                        tme.cbSize = sizeof(tme);
                        tme.dwFlags = TME_NONCLIENT | TME_LEAVE;
                        tme.hwndTrack = hWnd;
                        entry->trackingLeave = TrackMouseEvent(&tme) == TRUE;
                    }
                    SyncCompanion(*entry);
                }
                break;

            case WM_NCMOUSELEAVE:
                entry->hoverTitle = false;
                entry->trackingLeave = false;
                SyncCompanion(*entry);
                break;

            case WM_ENTERSIZEMOVE:
                entry->moving = true;
                SyncCompanion(*entry);
                break;

            case WM_MOVING:
            case WM_SIZING:
                if ((entry->moving || entry->hoverTitle) && lParam) {
                    RepositionCompanionToRect(entry->companion,
                        *reinterpret_cast<RECT*>(lParam),
                        true);
                }
                break;

            case WM_WINDOWPOSCHANGED:
                if (entry->moving || entry->hoverTitle)
                    SyncCompanion(*entry);
                break;

            case WM_EXITSIZEMOVE:
                entry->moving = false;
                SyncCompanion(*entry);
                break;

            case WM_SHOWWINDOW:
                SyncCompanion(*entry);
                break;
            }
        }
    }

    if (msg == WM_NCDESTROY || msg == WM_DESTROY) {
        HWND comp = FindCompanion(hWnd);
        if (comp && IsWindow(comp))
            DestroyWindow(comp);
        RemoveCompanion(hWnd);
    }

    return original
        ? CallWindowProcW(original, hWnd, msg, wParam, lParam)
        : DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ============================================================
//  PrefixTitle
// ============================================================
static void PrefixTitle(HWND hWnd)
{
    if (!(GetWindowLongW(hWnd, GWL_STYLE) & WS_CAPTION)) return;

    wchar_t title[512] = {};
    GetWindowTextW(hWnd, title, 512);

    wchar_t tag[96];
    StringCbPrintfW(tag, sizeof(tag), L"[Sandbox: %s] ", g_BoxName);
    if (wcsncmp(title, tag, wcslen(tag)) == 0) return;

    wchar_t newTitle[600];
    StringCbPrintfW(newTitle, sizeof(newTitle), L"%s%s", tag, title);
    SetWindowTextW(hWnd, newTitle);
}

// ============================================================
//  IsOurWindow — check if hWnd belongs to this process and is
//  a genuine top-level app window (not a tool/tray/companion)
// ============================================================
static bool IsOurWindow(HWND hWnd)
{
    if (!hWnd || !IsWindow(hWnd)) return false;

    // Must belong to this process
    DWORD pid = 0;
    GetWindowThreadProcessId(hWnd, &pid);
    if (pid != GetCurrentProcessId()) return false;

    // Must be a true top-level (no parent)
    if (GetParent(hWnd) != nullptr) return false;

    // Must have a caption
    if (!(GetWindowLongW(hWnd, GWL_STYLE) & WS_CAPTION)) return false;

    // Must not be one of our own companion windows
    wchar_t cls[64] = {};
    GetClassNameW(hWnd, cls, 64);
    if (wcscmp(cls, COMPANION_CLASS) == 0) return false;

    return true;
}

// ============================================================
//  AttachToWindow — subclass + create companion for a target
// ============================================================
static void AttachToWindow(HWND hWnd)
{
    if (!IsOurWindow(hWnd)) return;
    PrefixTitle(hWnd);
    CreateCompanion(hWnd);
}

// ============================================================
//  WinEventHook callback — tracks target window lifecycle
//  and position.  Installed in-process (WINEVENT_INCONTEXT).
// ============================================================
static void CALLBACK WinEventProc(
    HWINEVENTHOOK /*hHook*/,
    DWORD          event,
    HWND           hWnd,
    LONG           idObject,
    LONG           /*idChild*/,
    DWORD          /*idEventThread*/,
    DWORD          /*dwmsEventTime*/)
{
    // We only care about window-level events (not menu/scrollbar/etc.)
    if (idObject != OBJID_WINDOW) return;
    if (!hWnd) return;

    switch (event)
    {
    case EVENT_OBJECT_LOCATIONCHANGE:
    case EVENT_OBJECT_SHOW:
    case EVENT_OBJECT_CREATE:
    {
        HWND comp = FindCompanion(hWnd);
        if (comp) {
            std::lock_guard<std::recursive_mutex> lk(g_compMutex);
            if (auto* entry = FindCompanionEntryLocked(hWnd))
                SyncCompanion(*entry);
        }
        else {
            AttachToWindow(hWnd); // new window we haven't seen
        }
        break;
    }

    case EVENT_OBJECT_NAMECHANGE:
    {
        if (IsOurWindow(hWnd))
            PrefixTitle(hWnd);
        break;
    }

    case EVENT_OBJECT_HIDE:
    {
        HWND comp = FindCompanion(hWnd);
        if (comp) ShowWindow(comp, SW_HIDE);
        break;
    }

    case EVENT_OBJECT_DESTROY:
    {
        HWND comp = FindCompanion(hWnd);
        if (comp) {
            DestroyWindow(comp);
            RemoveCompanion(hWnd);
        }
        break;
    }

    case EVENT_SYSTEM_FOREGROUND:
    case EVENT_OBJECT_REORDER:
    {
        // Re-assert TOPMOST so we stay above the target after z-order changes
        std::lock_guard<std::recursive_mutex> lk(g_compMutex);
        if (auto* entry = FindCompanionEntryLocked(hWnd)) {
            SyncCompanion(*entry);
        }
        break;
    }
    }
}

// ============================================================
//  WH_CBT hook — fires HCBT_CREATEWND for windows on THIS thread
//  hModule=NULL → in-process only, never injected globally
// ============================================================
static LRESULT CALLBACK CbtHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HCBT_CREATEWND) {
        // Note: at HCBT_CREATEWND the window exists but WinEventHook
        // EVENT_OBJECT_SHOW hasn't fired yet. We defer to AttachToWindow
        // which is also called from WinEventProc on EVENT_OBJECT_SHOW,
        // so no double-attach (IsOurWindow + FindCompanion guard it).
        AttachToWindow((HWND)wParam);
    }
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

// ============================================================
//  EnumWindowsProc — bootstrap pass for already-open windows
// ============================================================
static BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM)
{
    AttachToWindow(hWnd);
    return TRUE;
}

// ============================================================
//  RegisterCompanionClass — register the companion window class
// ============================================================
static bool RegisterCompanionClass()
{
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = CompanionWndProc;
    wc.hInstance     = g_hModule;
    wc.hbrBackground = nullptr; // we paint ourselves
    wc.lpszClassName = COMPANION_CLASS;
    return RegisterClassExW(&wc) != 0 ||
           GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

// ============================================================
//  IAT patching — SHOpenFolderAndSelectItems + ShellExecuteW
// ============================================================
using PFN_SHOpenFolderAndSelectItems = HRESULT(WINAPI*)(
    PCIDLIST_ABSOLUTE, UINT, PCUITEMID_CHILD_ARRAY, DWORD);
using PFN_ShellExecuteW = HINSTANCE(WINAPI*)(
    HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);

static PFN_SHOpenFolderAndSelectItems g_origSHOpen        = nullptr;
static PFN_ShellExecuteW              g_origShellExecuteW = nullptr;

static std::string JsonEscapeUtf8(const char* text)
{
    std::string esc;
    if (!text) return esc;

    for (char c : std::string(text)) {
        switch (c) {
        case '\\': esc += "\\\\"; break;
        case '"':  esc += "\\\""; break;
        case '\b': esc += "\\b"; break;
        case '\f': esc += "\\f"; break;
        case '\n': esc += "\\n"; break;
        case '\r': esc += "\\r"; break;
        case '\t': esc += "\\t"; break;
        default:   esc += c; break;
        }
    }
    return esc;
}

static void NotifyHostOpenFolder(const wchar_t* realPath, bool selectTarget)
{
    HANDLE hPipe = CreateFileW(g_PipeName, GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, 0, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE) return;

    char boxUtf8[64]        = {};
    char pathUtf8[MAX_PATH*2] = {};
    WideCharToMultiByte(CP_UTF8,0,g_BoxName,-1,boxUtf8,sizeof(boxUtf8),nullptr,nullptr);
    WideCharToMultiByte(CP_UTF8,0,realPath, -1,pathUtf8,sizeof(pathUtf8),nullptr,nullptr);

    std::string esc = JsonEscapeUtf8(pathUtf8);

    char buf[1400];
    int len = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"cmd\":\"openFolder\",\"box\":\"%s\",\"path\":\"%s\",\"select\":\"%s\"}\n",
        boxUtf8, esc.c_str(), selectTarget ? "1" : "0");
    if (len <= 0) {
        CloseHandle(hPipe);
        return;
    }
    DWORD w = 0;
    WriteFile(hPipe, buf, (DWORD)len, &w, nullptr);
    CloseHandle(hPipe);
}

static bool PatchIAT(HMODULE hMod, const char* dll,
                     const char* fn, PROC newFn, PROC* oldFn)
{
    if (!hMod) return false;
    auto* dos  = (IMAGE_DOS_HEADER*)hMod;
    auto* nt   = (IMAGE_NT_HEADERS*)((BYTE*)hMod + dos->e_lfanew);
    auto& dir  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) return false;
    auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hMod + dir.VirtualAddress);
    for (; desc->Name; ++desc) {
        if (_stricmp((char*)((BYTE*)hMod+desc->Name), dll)) continue;
        auto* t  = (IMAGE_THUNK_DATA*)((BYTE*)hMod+desc->FirstThunk);
        auto* ot = (IMAGE_THUNK_DATA*)((BYTE*)hMod+desc->OriginalFirstThunk);
        for (; ot->u1.AddressOfData; ++t, ++ot) {
            if (IMAGE_SNAP_BY_ORDINAL(ot->u1.Ordinal)) continue;
            auto* ibn = (IMAGE_IMPORT_BY_NAME*)((BYTE*)hMod+ot->u1.AddressOfData);
            if (_stricmp((char*)ibn->Name, fn)) continue;
            DWORD old=0;
            VirtualProtect(&t->u1.Function,sizeof(PROC),PAGE_READWRITE,&old);
            if (oldFn) *oldFn=(PROC)t->u1.Function;
            t->u1.Function=(ULONG_PTR)newFn;
            VirtualProtect(&t->u1.Function,sizeof(PROC),old,&old);
            return true;
        }
    }
    return false;
}

static HRESULT WINAPI Hook_SHOpenFolderAndSelectItems(
    PCIDLIST_ABSOLUTE pidl, UINT c, PCUITEMID_CHILD_ARRAY a, DWORD f)
{
    wchar_t path[MAX_PATH]={};
    bool selectTarget = false;

    if (pidl && c > 0 && a && a[0]) {
        PIDLIST_ABSOLUTE full = ILCombine(pidl, a[0]);
        if (full) {
            if (SHGetPathFromIDListW(full, path))
                selectTarget = true;
            CoTaskMemFree(full);
        }
    }

    if ((selectTarget || SHGetPathFromIDListW(pidl,path))) {
        NotifyHostOpenFolder(path, selectTarget);
        return S_OK;
    }
    return g_origSHOpen ? g_origSHOpen(pidl,c,a,f) : E_FAIL;
}

static HINSTANCE WINAPI Hook_ShellExecuteW(
    HWND hw, LPCWSTR op, LPCWSTR file, LPCWSTR par, LPCWSTR dir, INT sh)
{
    bool isOpen = !op || !_wcsicmp(op,L"open") || !_wcsicmp(op,L"explore");
    if (isOpen && file) {
        DWORD a=GetFileAttributesW(file);
        if (a!=INVALID_FILE_ATTRIBUTES && (a&FILE_ATTRIBUTE_DIRECTORY)) {
            NotifyHostOpenFolder(file, false);
            return (HINSTANCE)(INT_PTR)42;
        }
    }
    return g_origShellExecuteW
        ? g_origShellExecuteW(hw,op,file,par,dir,sh)
        : (HINSTANCE)(INT_PTR)2;
}

// ============================================================
//  SandboxBorder_Init
// ============================================================
extern "C" SBAPI BOOL WINAPI SandboxBorder_Init(void)
{
    GetEnvironmentVariableW(SANDBOX_BORDER_BOX_ENV,
                            g_BoxName,     (DWORD)std::size(g_BoxName));
    GetEnvironmentVariableW(SANDBOX_BORDER_ROOT_ENV,
                            g_SandboxRoot, (DWORD)std::size(g_SandboxRoot));
    if (g_BoxName[0] == L'\0') return FALSE;

    // 1. Register the companion window class
    if (!RegisterCompanionClass()) return FALSE;

    // 2. Install in-process CBT hook (NULL module = this process only)
    g_cbtHook = SetWindowsHookExW(WH_CBT, CbtHookProc,
                                   nullptr,              // NULL = in-process
                                   GetCurrentThreadId());

    // 3. Install WinEventHook for this process.  Do not use
    //    WINEVENT_SKIPOWNTHREAD: in Notepad the target window is created on
    //    the same initial thread that loaded this DLL.
    g_winEventHook = SetWinEventHook(
        EVENT_OBJECT_CREATE,
        EVENT_OBJECT_NAMECHANGE,
        nullptr,                  // NULL = in-process (WINEVENT_INCONTEXT implied)
        WinEventProc,
        GetCurrentProcessId(),    // this process only
        0,                        // all threads
        WINEVENT_INCONTEXT);

    // Also hook foreground/reorder events which have higher IDs
    SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND,
                    nullptr, WinEventProc,
                    GetCurrentProcessId(), 0,
                    WINEVENT_INCONTEXT);

    // 4. Bootstrap: attach to any windows already open in this process
    EnumWindows(EnumWindowsProc, 0);

    // 5. IAT-patch Show-in-folder APIs
    HMODULE hExe   = GetModuleHandleW(nullptr);
    HMODULE hShell = GetModuleHandleW(L"shell32.dll");
    PatchIAT(hExe,"shell32.dll","SHOpenFolderAndSelectItems",
             (PROC)Hook_SHOpenFolderAndSelectItems,(PROC*)&g_origSHOpen);
    PatchIAT(hExe,"shell32.dll","ShellExecuteW",
             (PROC)Hook_ShellExecuteW,(PROC*)&g_origShellExecuteW);
    if (!g_origSHOpen && hShell)
        g_origSHOpen=(PFN_SHOpenFolderAndSelectItems)
            GetProcAddress(hShell,"SHOpenFolderAndSelectItems");
    if (!g_origShellExecuteW && hShell)
        g_origShellExecuteW=(PFN_ShellExecuteW)
            GetProcAddress(hShell,"ShellExecuteW");

    return TRUE;
}

// ============================================================
//  SandboxBorder_Uninit
// ============================================================
extern "C" SBAPI BOOL WINAPI SandboxBorder_Uninit(void)
{
    if (g_cbtHook)      { UnhookWindowsHookEx(g_cbtHook); g_cbtHook=nullptr; }
    if (g_winEventHook) { UnhookWinEvent(g_winEventHook); g_winEventHook=nullptr; }

    // Destroy all companion windows
    std::lock_guard<std::recursive_mutex> lk(g_compMutex);
    for (auto& e : g_companions) {
        if (IsWindow(e.target) && e.originalProc) {
            SetWindowLongPtrW(e.target, GWLP_WNDPROC,
                reinterpret_cast<LONG_PTR>(e.originalProc));
        }
        if (IsWindow(e.companion)) DestroyWindow(e.companion);
    }
    g_companions.clear();
    return TRUE;
}

// ============================================================
//  DllMain
// ============================================================
BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD reason, LPVOID)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_hModule = hInstance;
        DisableThreadLibraryCalls(hInstance);
        break;
    case DLL_PROCESS_DETACH:
        SandboxBorder_Uninit();
        break;
    }
    return TRUE;
}
