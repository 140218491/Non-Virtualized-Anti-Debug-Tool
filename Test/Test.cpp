#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <string.h>
#include <atomic>
#include <mutex>

std::atomic<bool> checksFunctioning(true);
std::mutex checksMutex;

void EnsureConsoleOpen() {
    AllocConsole();
    FILE* file;
    freopen_s(&file, "CONOUT$", "w", stdout);
    freopen_s(&file, "CONOUT$", "w", stderr);
    freopen_s(&file, "CONIN$", "r", stdin);
}

std::string GetExecutablePath() {
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    std::string::size_type pos = std::string(buffer).find_last_of("\\/");
    return std::string(buffer).substr(0, pos);
}

unsigned long GetFileSize(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file) {
        return 0;
    }
    return static_cast<unsigned long>(file.tellg());
}

void SelfCheckIntegrity() {
    std::string executablePath = GetExecutablePath() + "\\Test.exe";
    unsigned long currentFileSize = GetFileSize(executablePath);

    if (currentFileSize == 0) {
        exit(1);
    }

    std::cout << currentFileSize << std::endl;

    const unsigned long knownFileSize = 33280;

    if (currentFileSize != knownFileSize) {
        exit(1);
    }
}

#pragma optimize("", off)
bool IsDebuggerPresentCheck() {
    if (IsDebuggerPresent()) {
        std::lock_guard<std::mutex> lock(checksMutex);
        checksFunctioning = true;
        return true;
    }
    return false;
}
#pragma optimize("", on)

#pragma optimize("", off)
bool IsRemoteDebuggerPresent() {
    BOOL isDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
    if (isDebuggerPresent) {
        std::lock_guard<std::mutex> lock(checksMutex);
        checksFunctioning = true;
    }
    return isDebuggerPresent;
}
#pragma optimize("", on)

#pragma optimize("", off)
bool IsCommonDebuggerWindowPresent() {
    const wchar_t* debuggerWindows[] = {
        L"OLLYDBG",
        L"WinDbgFrameClass",
        L"x64dbg",
        L"IDAGenericWndClass",
        L"IDAView",
        L"ScyllaHide",
        L"TMainForm",
        L"TFrmMemoryView",
        L"Qt5153",
        L"ida",
        L"ida.exe",
        L"NLSvc.exe"
    };

    HWND hwnd = GetTopWindow(0);
    while (hwnd) {
        wchar_t className[256];
        GetClassName(hwnd, className, sizeof(className));

        wchar_t windowText[256];
        GetWindowText(hwnd, windowText, sizeof(windowText));

        for (const auto& debuggerWindow : debuggerWindows) {
            if (wcsstr(className, debuggerWindow) != NULL || wcsstr(windowText, debuggerWindow) != NULL) {
                std::lock_guard<std::mutex> lock(checksMutex);
                checksFunctioning = true;
                return true;
            }
        }

        hwnd = GetNextWindow(hwnd, GW_HWNDNEXT);
    }
    return false;
}
#pragma optimize("", on)

#pragma optimize("", off)
bool IsSpecificDebuggerRunning() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            char lowerProcessName[MAX_PATH];
            size_t size = wcslen(pe.szExeFile);
            wcstombs_s(&size, lowerProcessName, pe.szExeFile, size);
            _strlwr_s(lowerProcessName, size + 1);

            const char* knownDebuggersAndTools[] = {
                "cheatengine",
                "ida.exe",
                "ollydbg.exe",
                "windbg.exe",
                "x64dbg.exe",
                "scylla.exe",
                "de4dot.exe",
                "nlSvc.exe",
                "netlimiter.exe",
                "wireshark.exe",
                "proxifier.exe",
                "fiddler.exe",
                "charles.exe",
                "vpn.exe",
                "mitmproxy.exe",
                "processhacker.exe",
                "tcpview.exe"
            };

            for (const auto& tool : knownDebuggersAndTools) {
                if (strstr(lowerProcessName, tool) != NULL) {
                    std::lock_guard<std::mutex> lock(checksMutex);
                    checksFunctioning = true;
                    CloseHandle(hSnapshot);
                    return true;
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return false;
}
#pragma optimize("", on)

void ClearDebugRegisters() {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == GetCurrentProcessId()) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                if (hThread != NULL) {
                    CONTEXT ctx;
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

                    if (GetThreadContext(hThread, &ctx)) {
                        ctx.Dr0 = 0;
                        ctx.Dr1 = 0;
                        ctx.Dr2 = 0;
                        ctx.Dr3 = 0;
                        ctx.Dr6 = 0;
                        ctx.Dr7 = 0;

                        SetThreadContext(hThread, &ctx);
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }
    CloseHandle(hThreadSnap);
}

void OpenBrowserAndPlayVideo() {
    ShellExecuteW(NULL, L"open", L"https://www.youtube.com/watch?v=MbuHfR4KreQ", NULL, NULL, SW_SHOWNORMAL);
}

void MonitorChecks() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        std::lock_guard<std::mutex> lock(checksMutex);
        if (!checksFunctioning.load()) {
            *((volatile int*)0) = 0;
        }
        checksFunctioning = false;
    }
}

int main() {
    EnsureConsoleOpen();

    SelfCheckIntegrity();

    std::thread monitorThread(MonitorChecks);

    while (true) {
        bool detectionTriggered = false;

        if (IsDebuggerPresentCheck()) detectionTriggered = true;
        if (IsRemoteDebuggerPresent()) detectionTriggered = true;
        if (IsCommonDebuggerWindowPresent()) detectionTriggered = true;
        if (IsSpecificDebuggerRunning()) detectionTriggered = true;

        ClearDebugRegisters();

        if (detectionTriggered) {
            OpenBrowserAndPlayVideo();
            exit(1);
        }

        {
            std::lock_guard<std::mutex> lock(checksMutex);
            checksFunctioning = true;
        }
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    monitorThread.join();
    return 0;
}
