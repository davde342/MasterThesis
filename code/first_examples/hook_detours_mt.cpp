#include <windows.h>
#include <detours.h>
#include <tlhelp32.h>
#include <iostream>
#include <mutex>
#include <atomic>
#include <vector>

#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:DetourFinishHelperProcess=_DetourFinishHelperProcess@16,@1,NONAME")
#else 
#pragma comment(linker, "/EXPORT:DetourFinishHelperProcess=DetourFinishHelperProcess,@1,NONAME")
#endif

// Target functions pointer
typedef void (*ProcessTask)(int, const char*, int);
typedef void (*LogTaskResult)(int, const char*, double);

// Original function pointers resolved at runtime
static ProcessTask TrueProcessTask = nullptr;
static LogTaskResult TrueLogTaskResult = nullptr;

static std::mutex g_ConsoleMutex;

static std::atomic<int> g_TaskCount{0};
static std::atomic<int> g_ModifiedCount{0};
static std::atomic<int> g_ActiveHooks{0}; // Active hooks tracking for safe unload

// RAII helper to guarantee the active hook counter is decremented on scope exit,
// even if an exception is thrown in the hook callback or the original function.
struct HookGuard {
    HookGuard() { g_ActiveHooks++; }
    ~HookGuard() { g_ActiveHooks--; }
};

static bool g_HooksAttached = false;

void HookedProcessTask(int taskId, const char* taskType, int complexity) {
    HookGuard guard;
    g_TaskCount++;
    int modifiedComplexity = complexity;
    bool modified = false;

    // If the task is very slow (> 500ms), we intercept it and force
    // the complexity to 100ms
    if (complexity > 500) {
        modifiedComplexity = 100;
        g_ModifiedCount++;
        modified = true;
    }

    {
        //serialized logging
        std::lock_guard<std::mutex> lock(g_ConsoleMutex);
        std::cout << "[HOOK ProcessTask] TID: " << GetCurrentThreadId() << " | Task ID: " << taskId 
                  << " | Type: " << taskType << " | Original Complexity: " << complexity << "ms";
        if (modified) {
            std::cout << "Reduced to " << modifiedComplexity << "ms";
        }
        std::cout << std::endl;
    }

    TrueProcessTask(taskId, taskType, modifiedComplexity);
}

void HookedLogTaskResult(int taskId, const char* status, double result) {
    HookGuard guard;
    {
        std::lock_guard<std::mutex> lock(g_ConsoleMutex);
        std::cout << "[HOOK LogTaskResult] TID: " << GetCurrentThreadId() << " | Task ID: " << taskId 
                  << " | Status: " << status << " | Result: " << result 
                  << " | Stats: [Intercepted: " << g_TaskCount.load() << ", Modified: " << g_ModifiedCount.load() << "]"
                  << std::endl;
    }

    TrueLogTaskResult(taskId, status, result);
}


// Discovers all threads currently active in this process (except current thread)
// to stop/update their instruction pointers during detour transactions

std::vector<HANDLE> EnlistAllThreads() {
    std::vector<HANDLE> threadHandles;
    DWORD currentProcessId = GetCurrentProcessId();
    DWORD currentThreadId = GetCurrentThreadId();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return threadHandles;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == currentProcessId && te.th32ThreadID != currentThreadId) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (hThread) {
                    threadHandles.push_back(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);
    return threadHandles;
}


void AttachHooks() {
    HMODULE hExe = GetModuleHandle(NULL);
    if (!hExe) return;

    // Dynamically resolve target functions exported by the target executable
    TrueProcessTask = (ProcessTask)GetProcAddress(hExe, "ProcessTask");
    TrueLogTaskResult = (LogTaskResult)GetProcAddress(hExe, "LogTaskResult");

    if (!TrueProcessTask || !TrueLogTaskResult) {
        std::lock_guard<std::mutex> lock(g_ConsoleMutex);
        std::cerr << "[HOOK] Failed to resolve target functions" << std::endl;
        return;
    }

    std::vector<HANDLE> threads = EnlistAllThreads();

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    
    // Suspend and enlist all active threads in the process
    for (HANDLE hThread : threads) {
        DetourUpdateThread(hThread);
    }

    DetourAttach(&(PVOID&)TrueProcessTask, (PVOID)HookedProcessTask);
    DetourAttach(&(PVOID&)TrueLogTaskResult, (PVOID)HookedLogTaskResult);

    LONG error = DetourTransactionCommit();

    for (HANDLE hThread : threads) {
        CloseHandle(hThread);
    }

    {
        std::lock_guard<std::mutex> lock(g_ConsoleMutex);
        if (error == NO_ERROR) {
            g_HooksAttached = true;
            std::cout << "[HOOK] Dynamic detours attached. Suspended/Resumed " 
                      << threads.size() << " running worker threads." << std::endl;
        } else {
            std::cerr << "[HOOK] DetourTransactionCommit failed. Error code: " << error << std::endl;
        }
    }
}

void DetachHooks() {
    if (!g_HooksAttached) return;

    std::vector<HANDLE> threads = EnlistAllThreads();

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    for (HANDLE hThread : threads) {
        DetourUpdateThread(hThread);
    }

    DetourDetach(&(PVOID&)TrueProcessTask, (PVOID)HookedProcessTask);
    DetourDetach(&(PVOID&)TrueLogTaskResult, (PVOID)HookedLogTaskResult);

    LONG error = DetourTransactionCommit();

    for (HANDLE hThread : threads) {
        CloseHandle(hThread);
    }

    if (error == NO_ERROR) {
        g_HooksAttached = false;

        while (true) {
            // Wait for all threads currently known to be in the hooks to exit
            while (g_ActiveHooks.load() > 0) {
                SwitchToThread();
            }

            // This period allows any thread de-scheduled in the tiny window 
            // (after the detour jump but before the atomic increment or
            //  after the atomic decrement but before hook function epilogue) to wake up and run.
            Sleep(1000);

            if (g_ActiveHooks.load() == 0) {
                break;
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(g_ConsoleMutex);
        if (error == NO_ERROR) {
            std::cout << "[HOOK] hooks detached." << std::endl;
        } else {
            std::cerr << "[HOOK] failed on detach. Error code: " << error << std::endl;
        }
    }
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            // Disable thread attach/detach notifications to optimize performance
            DisableThreadLibraryCalls(hModule);
            AttachHooks();
            break;
        case DLL_PROCESS_DETACH:
            DetachHooks();
            break;
    }
    return TRUE;
}
