// ============================================================
//  SandboxExplorer.cpp
// ============================================================
#include "SandboxExplorer.h"
#include <filesystem>
#include <sstream>
#include <algorithm>
#include <cctype>
#include "StringUtil.h"
namespace fs = std::filesystem;

// ============================================================
SandboxExplorer::SandboxExplorer(ExplorerLogFn log)
    : m_log(std::move(log))
{}

SandboxExplorer::~SandboxExplorer()
{
    stopPipeServer();
}

// ============================================================
//  Named-pipe server
//
//  One pipe instance per connection (ConnectNamedPipe → read →
//  dispatch → disconnect loop).  The pipe name is fixed to the
//  box name, matching what the DLL writes to.
//
//  We use a single shared pipe name for all boxes:
//      \\.\pipe\SandboxFlt_Broker
//  and let the JSON payload carry the box name.  This avoids
//  creating one pipe per box and keeps the server simple.
// ============================================================
static constexpr wchar_t kPipeName[] =
    L"\\\\.\\pipe\\SandboxFlt_Broker";

void SandboxExplorer::startPipeServer(DriverManager& driver,
                                       SandboxEngine&  engine,
                                       const std::wstring& fsRootBase)
{
    if (m_running.exchange(true)) return;  // already running

    // Capture raw pointers.  driver and engine are MainWindow members whose
    // lifetime exceeds this thread — MainWindow::~MainWindow calls
    // stopPipeServer() (which joins the thread) before destroying m_driver
    // and m_engine, so these pointers are always valid while the thread runs.
    DriverManager* pDriver = &driver;
    SandboxEngine* pEngine = &engine;
    m_pipeThread = std::thread([this, pDriver, pEngine, fsRootBase]() {
        pipeServerLoop(pDriver, pEngine, fsRootBase);
    });
    log(L"[Explorer] Pipe server started: " + std::wstring(kPipeName));
}

void SandboxExplorer::stopPipeServer()
{
    if (!m_running.exchange(false)) return;

    // Wake up a blocked ConnectNamedPipe by opening + closing a dummy client
    HANDLE hDummy = CreateFileW(kPipeName, GENERIC_WRITE, 0,
                                nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDummy != INVALID_HANDLE_VALUE) CloseHandle(hDummy);

    if (m_pipeThread.joinable()) m_pipeThread.join();
    log(L"[Explorer] Pipe server stopped.");
}

void SandboxExplorer::pipeServerLoop(DriverManager* driver,
                                      SandboxEngine*  engine,
                                      std::wstring    fsRootBase)
{
    while (m_running.load()) {
        // Create a new named pipe instance for each connection
        HANDLE hPipe = CreateNamedPipeW(
            kPipeName,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            0, 4096, 0, nullptr);

        if (hPipe == INVALID_HANDLE_VALUE) {
            log(L"[Explorer] CreateNamedPipe failed: " +
                std::to_wstring(GetLastError()));
            Sleep(1000);
            continue;
        }

        // Block until a client connects
        BOOL connected = ConnectNamedPipe(hPipe, nullptr);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(hPipe);
            continue;
        }
        if (!m_running.load()) {
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            break;
        }

        // Read one message (up to 4 KB)
        char buf[4096] = {};
        DWORD read = 0;
        if (ReadFile(hPipe, buf, sizeof(buf) - 1, &read, nullptr) && read > 0) {
            buf[read] = '\0';
            std::string json(buf);

            // Parse: {"cmd":"openFolder","box":"Box00","path":"C:\\...","select":"1"}
            std::string cmd  = jsonGetField(json, "cmd");
            std::string box  = jsonGetField(json, "box");
            std::string path = jsonGetField(json, "path");
            std::string select = jsonGetField(json, "select");

            if (cmd == "openFolder" && !box.empty() && !path.empty()) {
                // Convert UTF-8 fields to wide strings
                std::wstring wBox  = StringUtil::utf8ToWide(box);
                std::wstring wPath = StringUtil::utf8ToWide(path);

                log(L"[Explorer] openFolder request: box=" + wBox +
                    L" path=" + wPath);

                openFolderInSandbox(*driver, *engine, wBox, wPath, fsRootBase,
                                    select == "1");
            }
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

// ============================================================
//  openFolderInSandbox
//
//  Launches:
//
//    explorer.exe "<realFolder>"
//    explorer.exe /select,"<realFile>"
//
//  inside the same box so the minifilter gives it the merged
//  (host + sandbox overlay) directory view while Explorer still
//  displays the normal host path, e.g. C:\Users\admin\Downloads.
//
//  The Explorer instance is:
//    - Assigned to the box's Job Object (via SandboxEngine::launch)
//    - Its PID is registered with the driver (addProcess)
//    - SandboxBorder.dll is injected into it for the yellow border
//
//  After injection, Explorer opens at the real path.  The
//  PostDirectoryControl hook in SandboxFlt_Filter.c merges
//  host entries + sandbox entries, so the user sees everything.
// ============================================================
bool SandboxExplorer::openFolderInSandbox(DriverManager&      driver,
                                           SandboxEngine&       engine,
                                           const std::wstring&  boxName,
                                           const std::wstring&  realPath,
                                           const std::wstring&  fsRootBase,
                                           bool                 selectTarget)
{
    // 1. Keep Explorer on the real path.  The Explorer process itself is
    //    sandboxed, so directory enumeration of this real folder is merged by
    //    the driver with the box overlay's matching relative path.
    std::wstring explorerArgs = selectTarget
        ? (L"/select,\"" + realPath + L"\"")
        : (L"\"" + realPath + L"\"");
    log(L"[Explorer] Explorer path: " + realPath +
        (selectTarget ? L" (select)" : L""));

    // 2. Launch Explorer sandboxed
    //    We use SandboxEngine::launch which:
    //      a) Creates a Job Object (KillOnClose=false so Explorer lives independently)
    //      b) Creates the private namespace
    //      c) Spawns explorer.exe suspended
    //    Then we register the PID with the driver and resume.
    wchar_t explorerPath[MAX_PATH] = {};
    GetWindowsDirectoryW(explorerPath, MAX_PATH);
    wcscat_s(explorerPath, L"\\explorer.exe");

    SandboxConfig cfg;
    cfg.boxName        = boxName;
    cfg.executablePath = explorerPath;
    cfg.commandLine    = explorerArgs;
    cfg.fsRootBase     = fsRootBase;
    cfg.restrictUI     = false;   // Explorer needs full UI access
    cfg.killOnClose    = false;   // Don't kill Explorer when we close

    SandboxedProcess sp = engine.launch(cfg);
    if (!sp.valid) {
        log(L"[Explorer] Failed to launch sandboxed Explorer.");
        return false;
    }

    // 5. Register with driver (so its file I/O is redirected)
    if (driver.isLoaded()) {
        // Box should already exist; addProcess is idempotent on collision
        bool pidOk = driver.addProcess(sp.pid, boxName);
        if (!pidOk) {
            log(L"[Explorer] Warning: addProcess failed for Explorer PID " +
                std::to_wstring(sp.pid) + L" — it will still run but without FS redirect");
        }
    }

    // 6. Inject the border DLL BEFORE resume (context hijack, same fix as
    //    the main Chrome injection path — avoids ERROR_ACCESS_DENIED=5 from
    //    JOB_OBJECT_UILIMIT_HANDLES blocking CreateRemoteThread on live processes).
    {
        std::wstring dllPath = defaultDllPath();
        if (!dllPath.empty()) {
            bool ok = engine.injectWhileSuspended(sp, dllPath);
            log(ok
                ? L"[Explorer] Context hijack installed for Explorer PID " + std::to_wstring(sp.pid)
                : L"[Explorer] Context hijack failed — yellow border unavailable for Explorer");
        } else {
            log(L"[Explorer] SandboxBorder.dll not found — yellow border unavailable.");
        }
    }

    // 7. Resume the process (stub runs LoadLibraryW then jumps to real entry)
    if (!engine.resume(sp)) {
        log(L"[Explorer] Failed to resume Explorer.");
        engine.release(sp);
        return false;
    }

    log(L"[Explorer] Sandboxed Explorer PID " +
        std::to_wstring(sp.pid) + L" running at: " + realPath);
    return true;
}

// ============================================================
//  jsonGetField  —  minimal JSON string field extractor
//  Returns raw UTF-8 value. Caller converts to wide as needed.
//  Handles simple flat JSON: {"key":"value","key2":"val2"}
//  Supports \\-escaped backslashes (path values).
// ============================================================
std::string SandboxExplorer::jsonGetField(const std::string& json,
                                           const std::string& key)
{
    std::string search = "\"" + key + "\":\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return {};
    pos += search.size();

    std::string val;
    bool escaped = false;
    for (size_t i = pos; i < json.size(); ++i) {
        char c = json[i];
        if (escaped) {
            if      (c == '\\') val += '\\';
            else if (c == '"')  val += '"';
            else if (c == 'n')  val += '\n';
            else if (c == 't')  val += '\t';
            else                val += c;
            escaped = false;
        } else if (c == '\\') {
            escaped = true;
        } else if (c == '"') {
            break;
        } else {
            val += c;
        }
    }
    return val;   // raw UTF-8; caller converts to wide as needed
}

// Helper: UTF-8 std::string -> std::wstring
static std::wstring utf8ToWide(const std::string& s)
{
    if (s.empty()) return {};
    int wLen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (wLen <= 0) return {};
    std::wstring w(wLen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), wLen);
    // MultiByteToWideChar with -1 includes the null terminator in the count
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

// ============================================================
//  defaultDllPath — SandboxBorder.dll next to the host EXE
// ============================================================
std::wstring SandboxExplorer::defaultDllPath()
{
    wchar_t exeBuf[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exeBuf, MAX_PATH);
    fs::path p(exeBuf);
    fs::path dll = p.parent_path() / L"SandboxBorder.dll";
    if (fs::exists(dll))
        return dll.wstring();
    return {};
}
