#pragma once
// ============================================================
//  SandboxEngine.h
//
//  Implements three Sandboxie-style isolation techniques:
//
//  1. OBJECT NAMESPACE VIRTUALIZATION
//     Creates a private NT Object Directory (e.g. \Sandbox\Box0\)
//     so that named kernel objects (mutexes, pipes, shared mem)
//     created by sandboxed processes land in an isolated
//     namespace instead of \BaseNamedObjects\.
//     → This is why Chrome C spawns its own Network Service.
//
//  2. JOB OBJECT CONTAINMENT
//     Assigns the sandboxed process tree to a Windows Job Object
//     with restricted UIRestrictions and kill-on-close semantics.
//     All child processes are automatically added to the same Job.
//
//  3. FILESYSTEM REDIRECTION  (user-mode approximation)
//     Passes a custom --user-data-dir (or env var override) so
//     the child process writes to a sandbox folder.
//     Full Sandboxie does this in kernel via NtCreateFile hooks;
//     we demonstrate the principle at the process-launch level.
//
// ============================================================
#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include "NtDefs.h"

// ---- Result from launching a sandboxed process --------------
struct SandboxedProcess {
    DWORD  pid          = 0;
    HANDLE hProcess     = nullptr;
    HANDLE hThread      = nullptr;
    HANDLE hJob         = nullptr;       // Job Object handle
    HANDLE hNamespaceDir= nullptr;       // NT directory object
    std::wstring boxName;
    std::wstring fsRoot;                 // sandbox FS root path
    bool   valid        = false;
    bool   suspended    = false;
};

// ---- Configuration for one sandbox box ----------------------
struct SandboxConfig {
    std::wstring boxName;           // e.g. L"Box0"
    std::wstring executablePath;    // full path to .exe
    std::wstring commandLine;       // extra args
    std::wstring fsRootBase;        // e.g. L"C:\\Sandbox"
    bool restrictUI     = true;     // block SetWindowsHook etc.
    bool killOnClose    = true;     // terminate tree when job closed
    bool inheritConsole = false;
};

// ---- Callback types -----------------------------------------
using LogCallback = std::function<void(const std::wstring&)>;

// ============================================================
class SandboxEngine {
public:
    explicit SandboxEngine(LogCallback log = nullptr);
    ~SandboxEngine();

    // Launch a process inside a new sandbox box.
    // Returns a SandboxedProcess; caller must call release() when done.
    SandboxedProcess launch(const SandboxConfig& cfg);

    // Terminate and clean up a sandboxed process.
    void release(SandboxedProcess& sp);

    // Resume the initial thread after the driver has registered the PID.
    bool resume(SandboxedProcess& sp);

    // Query if a PID is still alive
    static bool isAlive(DWORD pid);
    static bool isAlive(const SandboxedProcess& sp);

    // Describe what the engine did (for the UI log)
    static std::wstring describeJob(HANDLE hJob);

private:
    LogCallback m_log;

    // Step 1 – carve private NT object namespace
    HANDLE createPrivateNamespace(const std::wstring& boxName);

    // Step 2 – create & configure Job Object
    HANDLE createJobObject(const SandboxConfig& cfg);

    // Step 3 – spawn process suspended, assign to job, resume
    bool   spawnInJob(const SandboxConfig& cfg,
                      HANDLE hJob,
                      HANDLE hNsDir,
                      SandboxedProcess& out);

    // Step 4 – prepare sandbox filesystem root
    std::wstring prepareFsRoot(const std::wstring& base,
                                const std::wstring& boxName);

    void log(const std::wstring& msg);
};
