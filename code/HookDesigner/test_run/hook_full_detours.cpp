#include <windows.h>
#include <detours.h>
#include <tlhelp32.h>
#include <iostream>
#include <sstream>
#include <mutex>
#include <atomic>
#include <vector>
#include <string>

#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:DetourFinishHelperProcess=_DetourFinishHelperProcess@16,@1,NONAME")
#else 
#pragma comment(linker, "/EXPORT:DetourFinishHelperProcess=DetourFinishHelperProcess,@1,NONAME")
#endif

// Global synchronizations
static std::atomic<int> g_ActiveHooks{0};
static bool g_HooksAttached = false;
static LARGE_INTEGER g_PerfFrequency = {0};

// RAII helper to track active hook execution count
struct HookGuard {
    HookGuard() { g_ActiveHooks++; }
    ~HookGuard() { g_ActiveHooks--; }
};

#include "policy_logic.cpp"

// Inner helper under SEH protection to copy string without instantiating C++ objects
static bool CopyStringImpl(const char* source, char* dest, size_t maxChars) {
    __try {
        for (size_t i = 0; i < maxChars; ++i) {
            char c = source[i];
            dest[i] = c;
            if (c == '\0') {
                return true;
            }
        }
        dest[maxChars] = '\0';
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// copy wrapper with std::string allocation
static std::string CopyString(const char* source, size_t maxChars = 128) {
    if (!source) {
        return "null";
    }
    std::vector<char> buffer(maxChars + 1, 0);
    if (CopyStringImpl(source, buffer.data(), maxChars)) {
        return std::string(buffer.data());
    }
    return "<INVALID_MEMORY>";
}

// Inner helper under SEH protection to dereference pointer without instantiating C++ objects
template <typename T>
static bool ReadPointerImpl(const T* ptr, T& outVal) {
    __try {
        outVal = *ptr;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Outer read wrapper
template <typename T>
static T ReadPointer(const T* ptr, T fallback = T()) {
    if (!ptr) {
        return fallback;
    }
    T val = fallback;
    if (ReadPointerImpl(ptr, val)) {
        return val;
    }
    return fallback;
}

// Helper to log SEH exceptions to avoid C2712 compiler errors in __try/__except functions
static void LogSEHException(const char* logicName, const char* functionName, DWORD exceptionCode) {
    std::ostringstream ss;
    ss << "[CRITICAL SCADA HOOK] SEH Exception 0x" << std::hex << exceptionCode << std::dec 
       << " caught in " << logicName << " of " << functionName << std::endl;
    std::cerr << ss.str();
}

// Using set for avoiding double definition in case of shared pre/post logic
bool RunPreLogic_SharedPacketPreHook(double & complexityWeight) {
    __try {
        SharedPacketPreHook(complexityWeight);
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        LogSEHException("pre_logic", "SharedPacketPreHook", GetExceptionCode());
        return false;
    }
}


bool RunPreLogic_GenericEnterLog() {
    __try {
        GenericEnterLog();
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        LogSEHException("pre_logic", "GenericEnterLog", GetExceptionCode());
        return false;
    }
}

bool RunPostLogic_LogTaskResult_post(int & taskId) {
    __try {
        LogTaskResult_post(taskId);
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        LogSEHException("post_logic", "LogTaskResult_post", GetExceptionCode());
        return false;
    }
}
bool RunPreLogic_ProcessCommandSignal_pre(double *& payloadValue) {
    __try {
        ProcessCommandSignal_pre(payloadValue);
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        LogSEHException("pre_logic", "ProcessCommandSignal_pre", GetExceptionCode());
        return false;
    }
}

bool RunPostLogic_ProcessCommandSignal_post(int & result,char *& responseBuffer) {
    __try {
        ProcessCommandSignal_post(result,responseBuffer);
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        LogSEHException("post_logic", "ProcessCommandSignal_post", GetExceptionCode());
        return false;
    }
}
bool RunPreLogic_SharedDoubleAction_pre(double & val) {
    __try {
        SharedDoubleAction_pre(val);
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        LogSEHException("pre_logic", "SharedDoubleAction_pre", GetExceptionCode());
        return false;
    }
}


bool RunPreLogic_ProcessDataPoint_pre(DataPoint *& dp) {
    __try {
        ProcessDataPoint_pre(dp);
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        LogSEHException("pre_logic", "ProcessDataPoint_pre", GetExceptionCode());
        return false;
    }
}

bool RunPreLogic_PerformCriticalTask_pre(int & taskID) {
    __try {
        PerformCriticalTask_pre(taskID);
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        LogSEHException("pre_logic", "PerformCriticalTask_pre", GetExceptionCode());
        return false;
    }
}



// Target functions typedefs and pointers
typedef int (*TrueParseProprietaryPacket_t)(void * packetBuffer,double complexityWeight);
static TrueParseProprietaryPacket_t TrueParseProprietaryPacket = nullptr;
typedef int (*TrueParseProprietaryPacket2_t)(void * packetBuffer,double complexityWeight);
static TrueParseProprietaryPacket2_t TrueParseProprietaryPacket2 = nullptr;
typedef void (*TrueLogTaskResult_t)(int taskId,const char * status,double result);
static TrueLogTaskResult_t TrueLogTaskResult = nullptr;
typedef int (*TrueProcessCommandSignal_t)(int cmdId,double * payloadValue,char * responseBuffer);
static TrueProcessCommandSignal_t TrueProcessCommandSignal = nullptr;
typedef int (*TrueUpdateSensor_t)(int id,double val);
static TrueUpdateSensor_t TrueUpdateSensor = nullptr;
typedef int (*TrueCalibrateDevice_t)(int id,double val);
static TrueCalibrateDevice_t TrueCalibrateDevice = nullptr;
typedef int (*TrueProcessDataPoint_t)(DataPoint * dp);
static TrueProcessDataPoint_t TrueProcessDataPoint = nullptr;
typedef void (WINAPI *TruePerformCriticalTask_t)(int taskID);
static TruePerformCriticalTask_t TruePerformCriticalTask = nullptr;
typedef int (*TrueProcessNestedSignal_t)(double ** ppValue);
static TrueProcessNestedSignal_t TrueProcessNestedSignal = nullptr;

// Enlist all thread handles to suspend/resume in Detours transaction
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

// Hook Implementations
int HookedParseProprietaryPacket(void * packetBuffer,double complexityWeight) {
    HookGuard guard;


    // Capture arguments on entry
    void * input_packetBuffer = packetBuffer;
    double input_complexityWeight = complexityWeight;

    LARGE_INTEGER start_time_ParseProprietaryPacket;
    QueryPerformanceCounter(&start_time_ParseProprietaryPacket);


    // Pre-logic execution
    RunPreLogic_SharedPacketPreHook(complexityWeight);

    // Call Original
    int __hook_result = TrueParseProprietaryPacket(packetBuffer,complexityWeight);
    int __hook_input_result = __hook_result;

    // Post-logic execution

    LARGE_INTEGER end_time_ParseProprietaryPacket;
    QueryPerformanceCounter(&end_time_ParseProprietaryPacket);
    double elapsed_ms_ParseProprietaryPacket = (double)(end_time_ParseProprietaryPacket.QuadPart - start_time_ParseProprietaryPacket.QuadPart) * 1000.0 / g_PerfFrequency.QuadPart;


    // Capture arguments on exit
    void * output_packetBuffer = packetBuffer;
    double output_complexityWeight = complexityWeight;

    std::ostringstream ss;
    ss << "[HOOK ParseProprietaryPacket] TID: " << GetCurrentThreadId();
    if (input_packetBuffer == output_packetBuffer) {
        ss << " | packetBuffer: " << input_packetBuffer;
    } else {
        ss << " | packetBuffer: " << input_packetBuffer << " -> " << output_packetBuffer;
    }
    if (input_complexityWeight == output_complexityWeight) {
        ss << " | complexityWeight: " << input_complexityWeight;
    } else {
        ss << " | complexityWeight: " << input_complexityWeight << " -> " << output_complexityWeight;
    }
    if (__hook_input_result == __hook_result) {
        ss << " | result: " << __hook_result;
    } else {
        ss << " | result: " << __hook_input_result << " -> " << __hook_result;
    }
    ss << " | Latency: " << elapsed_ms_ParseProprietaryPacket << " ms";
    ss << std::endl;
    std::cout << ss.str();



    return __hook_result;
}
int HookedParseProprietaryPacket2(void * packetBuffer,double complexityWeight) {
    HookGuard guard;


    // Capture arguments on entry
    void * input_packetBuffer = packetBuffer;
    double input_complexityWeight = complexityWeight;

    LARGE_INTEGER start_time_ParseProprietaryPacket2;
    QueryPerformanceCounter(&start_time_ParseProprietaryPacket2);


    // Pre-logic execution
    RunPreLogic_SharedPacketPreHook(complexityWeight);

    // Call Original
    int __hook_result = TrueParseProprietaryPacket2(packetBuffer,complexityWeight);
    int __hook_input_result = __hook_result;

    // Post-logic execution

    LARGE_INTEGER end_time_ParseProprietaryPacket2;
    QueryPerformanceCounter(&end_time_ParseProprietaryPacket2);
    double elapsed_ms_ParseProprietaryPacket2 = (double)(end_time_ParseProprietaryPacket2.QuadPart - start_time_ParseProprietaryPacket2.QuadPart) * 1000.0 / g_PerfFrequency.QuadPart;


    // Capture arguments on exit
    void * output_packetBuffer = packetBuffer;
    double output_complexityWeight = complexityWeight;

    std::ostringstream ss;
    ss << "[HOOK ParseProprietaryPacket2] TID: " << GetCurrentThreadId();
    if (input_packetBuffer == output_packetBuffer) {
        ss << " | packetBuffer: " << input_packetBuffer;
    } else {
        ss << " | packetBuffer: " << input_packetBuffer << " -> " << output_packetBuffer;
    }
    if (input_complexityWeight == output_complexityWeight) {
        ss << " | complexityWeight: " << input_complexityWeight;
    } else {
        ss << " | complexityWeight: " << input_complexityWeight << " -> " << output_complexityWeight;
    }
    if (__hook_input_result == __hook_result) {
        ss << " | result: " << __hook_result;
    } else {
        ss << " | result: " << __hook_input_result << " -> " << __hook_result;
    }
    ss << " | Latency: " << elapsed_ms_ParseProprietaryPacket2 << " ms";
    ss << std::endl;
    std::cout << ss.str();



    return __hook_result;
}
void HookedLogTaskResult(int taskId,const char * status,double result) {
    HookGuard guard;


    // Capture arguments on entry
    int input_taskId = taskId;
    std::string input_status = CopyString(status);
    double input_result = result;

    LARGE_INTEGER start_time_LogTaskResult;
    QueryPerformanceCounter(&start_time_LogTaskResult);


    // Pre-logic execution
    RunPreLogic_GenericEnterLog();

    // Call Original
    TrueLogTaskResult(taskId,status,result);

    // Post-logic execution
    RunPostLogic_LogTaskResult_post(taskId);

    LARGE_INTEGER end_time_LogTaskResult;
    QueryPerformanceCounter(&end_time_LogTaskResult);
    double elapsed_ms_LogTaskResult = (double)(end_time_LogTaskResult.QuadPart - start_time_LogTaskResult.QuadPart) * 1000.0 / g_PerfFrequency.QuadPart;


    // Capture arguments on exit
    int output_taskId = taskId;
    std::string output_status = CopyString(status);
    double output_result = result;

    std::ostringstream ss;
    ss << "[HOOK LogTaskResult] TID: " << GetCurrentThreadId();
    if (input_taskId == output_taskId) {
        ss << " | taskId: " << input_taskId;
    } else {
        ss << " | taskId: " << input_taskId << " -> " << output_taskId;
    }
    if (input_status == output_status) {
        ss << " | status: " << input_status;
    } else {
        ss << " | status: " << input_status << " -> " << output_status;
    }
    if (input_result == output_result) {
        ss << " | result: " << input_result;
    } else {
        ss << " | result: " << input_result << " -> " << output_result;
    }
    ss << " | Latency: " << elapsed_ms_LogTaskResult << " ms";
    ss << std::endl;
    std::cout << ss.str();



}
int HookedProcessCommandSignal(int cmdId,double * payloadValue,char * responseBuffer) {
    HookGuard guard;


    // Capture arguments on entry
    int input_cmdId = cmdId;
    double input_payloadValue = ReadPointer(payloadValue);

    LARGE_INTEGER start_time_ProcessCommandSignal;
    QueryPerformanceCounter(&start_time_ProcessCommandSignal);


    // Pre-logic execution
    RunPreLogic_ProcessCommandSignal_pre(payloadValue);

    // Call Original
    int __hook_result = TrueProcessCommandSignal(cmdId,payloadValue,responseBuffer);
    int __hook_input_result = __hook_result;

    // Post-logic execution
    RunPostLogic_ProcessCommandSignal_post(__hook_result,responseBuffer);

    LARGE_INTEGER end_time_ProcessCommandSignal;
    QueryPerformanceCounter(&end_time_ProcessCommandSignal);
    double elapsed_ms_ProcessCommandSignal = (double)(end_time_ProcessCommandSignal.QuadPart - start_time_ProcessCommandSignal.QuadPart) * 1000.0 / g_PerfFrequency.QuadPart;


    // Capture arguments on exit
    int output_cmdId = cmdId;
    double output_payloadValue = ReadPointer(payloadValue);

    std::ostringstream ss;
    ss << "[HOOK ProcessCommandSignal] TID: " << GetCurrentThreadId();
    if (input_cmdId == output_cmdId) {
        ss << " | cmdId: " << input_cmdId;
    } else {
        ss << " | cmdId: " << input_cmdId << " -> " << output_cmdId;
    }
    if (input_payloadValue == output_payloadValue) {
        ss << " | payloadValue: " << input_payloadValue;
    } else {
        ss << " | payloadValue: " << input_payloadValue << " -> " << output_payloadValue;
    }
    if (__hook_input_result == __hook_result) {
        ss << " | result: " << __hook_result;
    } else {
        ss << " | result: " << __hook_input_result << " -> " << __hook_result;
    }
    ss << " | Latency: " << elapsed_ms_ProcessCommandSignal << " ms";
    ss << std::endl;
    std::cout << ss.str();



    return __hook_result;
}
int HookedUpdateSensor(int id,double val) {
    HookGuard guard;


    // Capture arguments on entry
    int input_id = id;
    double input_val = val;

    LARGE_INTEGER start_time_UpdateSensor;
    QueryPerformanceCounter(&start_time_UpdateSensor);


    // Pre-logic execution
    RunPreLogic_SharedDoubleAction_pre(val);

    // Call Original
    int __hook_result = TrueUpdateSensor(id,val);
    int __hook_input_result = __hook_result;

    // Post-logic execution

    LARGE_INTEGER end_time_UpdateSensor;
    QueryPerformanceCounter(&end_time_UpdateSensor);
    double elapsed_ms_UpdateSensor = (double)(end_time_UpdateSensor.QuadPart - start_time_UpdateSensor.QuadPart) * 1000.0 / g_PerfFrequency.QuadPart;


    // Capture arguments on exit
    int output_id = id;
    double output_val = val;

    std::ostringstream ss;
    ss << "[HOOK UpdateSensor] TID: " << GetCurrentThreadId();
    if (input_id == output_id) {
        ss << " | id: " << input_id;
    } else {
        ss << " | id: " << input_id << " -> " << output_id;
    }
    if (input_val == output_val) {
        ss << " | val: " << input_val;
    } else {
        ss << " | val: " << input_val << " -> " << output_val;
    }
    if (__hook_input_result == __hook_result) {
        ss << " | result: " << __hook_result;
    } else {
        ss << " | result: " << __hook_input_result << " -> " << __hook_result;
    }
    ss << " | Latency: " << elapsed_ms_UpdateSensor << " ms";
    ss << std::endl;
    std::cout << ss.str();



    return __hook_result;
}
int HookedCalibrateDevice(int id,double val) {
    HookGuard guard;


    // Capture arguments on entry
    int input_id = id;
    double input_val = val;

    LARGE_INTEGER start_time_CalibrateDevice;
    QueryPerformanceCounter(&start_time_CalibrateDevice);


    // Pre-logic execution
    RunPreLogic_SharedDoubleAction_pre(val);

    // Call Original
    int __hook_result = TrueCalibrateDevice(id,val);
    int __hook_input_result = __hook_result;

    // Post-logic execution

    LARGE_INTEGER end_time_CalibrateDevice;
    QueryPerformanceCounter(&end_time_CalibrateDevice);
    double elapsed_ms_CalibrateDevice = (double)(end_time_CalibrateDevice.QuadPart - start_time_CalibrateDevice.QuadPart) * 1000.0 / g_PerfFrequency.QuadPart;


    // Capture arguments on exit
    int output_id = id;
    double output_val = val;

    std::ostringstream ss;
    ss << "[HOOK CalibrateDevice] TID: " << GetCurrentThreadId();
    if (input_id == output_id) {
        ss << " | id: " << input_id;
    } else {
        ss << " | id: " << input_id << " -> " << output_id;
    }
    if (input_val == output_val) {
        ss << " | val: " << input_val;
    } else {
        ss << " | val: " << input_val << " -> " << output_val;
    }
    if (__hook_input_result == __hook_result) {
        ss << " | result: " << __hook_result;
    } else {
        ss << " | result: " << __hook_input_result << " -> " << __hook_result;
    }
    ss << " | Latency: " << elapsed_ms_CalibrateDevice << " ms";
    ss << std::endl;
    std::cout << ss.str();



    return __hook_result;
}
int HookedProcessDataPoint(DataPoint * dp) {
    HookGuard guard;


    // Capture arguments on entry
    DataPoint input_dp = ReadPointer(dp);

    LARGE_INTEGER start_time_ProcessDataPoint;
    QueryPerformanceCounter(&start_time_ProcessDataPoint);


    // Pre-logic execution
    RunPreLogic_ProcessDataPoint_pre(dp);

    // Call Original
    int __hook_result = TrueProcessDataPoint(dp);
    int __hook_input_result = __hook_result;

    // Post-logic execution

    LARGE_INTEGER end_time_ProcessDataPoint;
    QueryPerformanceCounter(&end_time_ProcessDataPoint);
    double elapsed_ms_ProcessDataPoint = (double)(end_time_ProcessDataPoint.QuadPart - start_time_ProcessDataPoint.QuadPart) * 1000.0 / g_PerfFrequency.QuadPart;


    // Capture arguments on exit
    DataPoint output_dp = ReadPointer(dp);

    std::ostringstream ss;
    ss << "[HOOK ProcessDataPoint] TID: " << GetCurrentThreadId();
    if (input_dp == output_dp) {
        ss << " | dp: " << input_dp;
    } else {
        ss << " | dp: " << input_dp << " -> " << output_dp;
    }
    if (__hook_input_result == __hook_result) {
        ss << " | result: " << __hook_result;
    } else {
        ss << " | result: " << __hook_input_result << " -> " << __hook_result;
    }
    ss << " | Latency: " << elapsed_ms_ProcessDataPoint << " ms";
    ss << std::endl;
    std::cout << ss.str();



    return __hook_result;
}
void WINAPI HookedPerformCriticalTask(int taskID) {
    HookGuard guard;


    // Capture arguments on entry
    int input_taskID = taskID;

    LARGE_INTEGER start_time_PerformCriticalTask;
    QueryPerformanceCounter(&start_time_PerformCriticalTask);


    // Pre-logic execution
    RunPreLogic_PerformCriticalTask_pre(taskID);

    // Call Original
    TruePerformCriticalTask(taskID);

    // Post-logic execution

    LARGE_INTEGER end_time_PerformCriticalTask;
    QueryPerformanceCounter(&end_time_PerformCriticalTask);
    double elapsed_ms_PerformCriticalTask = (double)(end_time_PerformCriticalTask.QuadPart - start_time_PerformCriticalTask.QuadPart) * 1000.0 / g_PerfFrequency.QuadPart;


    // Capture arguments on exit
    int output_taskID = taskID;

    std::ostringstream ss;
    ss << "[HOOK PerformCriticalTask] TID: " << GetCurrentThreadId();
    if (input_taskID == output_taskID) {
        ss << " | taskID: " << input_taskID;
    } else {
        ss << " | taskID: " << input_taskID << " -> " << output_taskID;
    }
    ss << " | Latency: " << elapsed_ms_PerformCriticalTask << " ms";
    ss << std::endl;
    std::cout << ss.str();



}
int HookedProcessNestedSignal(double ** ppValue) {
    HookGuard guard;


    // Capture arguments on entry
    double input_ppValue = ReadPointer(ReadPointer(ppValue));

    LARGE_INTEGER start_time_ProcessNestedSignal;
    QueryPerformanceCounter(&start_time_ProcessNestedSignal);


    // Pre-logic execution

    // Call Original
    int __hook_result = TrueProcessNestedSignal(ppValue);
    int __hook_input_result = __hook_result;

    // Post-logic execution

    LARGE_INTEGER end_time_ProcessNestedSignal;
    QueryPerformanceCounter(&end_time_ProcessNestedSignal);
    double elapsed_ms_ProcessNestedSignal = (double)(end_time_ProcessNestedSignal.QuadPart - start_time_ProcessNestedSignal.QuadPart) * 1000.0 / g_PerfFrequency.QuadPart;


    // Capture arguments on exit
    double output_ppValue = ReadPointer(ReadPointer(ppValue));

    std::ostringstream ss;
    ss << "[HOOK ProcessNestedSignal] TID: " << GetCurrentThreadId();
    if (input_ppValue == output_ppValue) {
        ss << " | ppValue: " << input_ppValue;
    } else {
        ss << " | ppValue: " << input_ppValue << " -> " << output_ppValue;
    }
    ss << " | Latency: " << elapsed_ms_ProcessNestedSignal << " ms";
    ss << std::endl;
    std::cout << ss.str();



    return __hook_result;
}



// Attach / Detach Transactions
extern "C" __declspec(dllexport) void InitializeHooks() {
    QueryPerformanceFrequency(&g_PerfFrequency);
    {
        HMODULE hMod = GetModuleHandleA("scada_engine.exe");
        if (hMod) {
            TrueParseProprietaryPacket = (TrueParseProprietaryPacket_t)((char*)hMod + 0x1000);
        } else {
            TrueParseProprietaryPacket = nullptr;
        }
    }
    if (!TrueParseProprietaryPacket) {
        std::cerr << "[WARNING] Failed to resolve target function: 'ParseProprietaryPacket' (check if module is loaded or function is exported)" << std::endl;
    }
    {
        HMODULE hMod = GetModuleHandleA("scada_engine.exe");
        if (hMod) {
            TrueParseProprietaryPacket2 = (TrueParseProprietaryPacket2_t)((char*)hMod + 0x1000);
        } else {
            TrueParseProprietaryPacket2 = nullptr;
        }
    }
    if (!TrueParseProprietaryPacket2) {
        std::cerr << "[WARNING] Failed to resolve target function: 'ParseProprietaryPacket2' (check if module is loaded or function is exported)" << std::endl;
    }
    {
        HMODULE hMod = GetModuleHandleA("scada_engine.exe");
        if (hMod) {
            TrueLogTaskResult = (TrueLogTaskResult_t)GetProcAddress(hMod, "LogTaskResult");
        } else {
            TrueLogTaskResult = nullptr;
        }
    }
    if (!TrueLogTaskResult) {
        std::cerr << "[WARNING] Failed to resolve target function: 'LogTaskResult' (check if module is loaded or function is exported)" << std::endl;
    }
    {
        HMODULE hMod = GetModuleHandleA("scada_engine.exe");
        if (hMod) {
            TrueProcessCommandSignal = (TrueProcessCommandSignal_t)GetProcAddress(hMod, "ProcessCommandSignal");
        } else {
            TrueProcessCommandSignal = nullptr;
        }
    }
    if (!TrueProcessCommandSignal) {
        std::cerr << "[WARNING] Failed to resolve target function: 'ProcessCommandSignal' (check if module is loaded or function is exported)" << std::endl;
    }
    {
        HMODULE hMod = GetModuleHandleA("scada_engine.exe");
        if (hMod) {
            TrueUpdateSensor = (TrueUpdateSensor_t)((char*)hMod + 0x1000);
        } else {
            TrueUpdateSensor = nullptr;
        }
    }
    if (!TrueUpdateSensor) {
        std::cerr << "[WARNING] Failed to resolve target function: 'UpdateSensor' (check if module is loaded or function is exported)" << std::endl;
    }
    {
        HMODULE hMod = GetModuleHandleA("scada_engine.exe");
        if (hMod) {
            TrueCalibrateDevice = (TrueCalibrateDevice_t)((char*)hMod + 0x1000);
        } else {
            TrueCalibrateDevice = nullptr;
        }
    }
    if (!TrueCalibrateDevice) {
        std::cerr << "[WARNING] Failed to resolve target function: 'CalibrateDevice' (check if module is loaded or function is exported)" << std::endl;
    }
    {
        HMODULE hMod = GetModuleHandleA("scada_engine.exe");
        if (hMod) {
            TrueProcessDataPoint = (TrueProcessDataPoint_t)GetProcAddress(hMod, "ProcessDataPoint");
        } else {
            TrueProcessDataPoint = nullptr;
        }
    }
    if (!TrueProcessDataPoint) {
        std::cerr << "[WARNING] Failed to resolve target function: 'ProcessDataPoint' (check if module is loaded or function is exported)" << std::endl;
    }
    {
        HMODULE hMod = GetModuleHandleA("scada_engine.exe");
        if (hMod) {
            TruePerformCriticalTask = (TruePerformCriticalTask_t)GetProcAddress(hMod, "PerformCriticalTask");
        } else {
            TruePerformCriticalTask = nullptr;
        }
    }
    if (!TruePerformCriticalTask) {
        std::cerr << "[WARNING] Failed to resolve target function: 'PerformCriticalTask' (check if module is loaded or function is exported)" << std::endl;
    }
    {
        HMODULE hMod = GetModuleHandleA("scada_engine.exe");
        if (hMod) {
            TrueProcessNestedSignal = (TrueProcessNestedSignal_t)GetProcAddress(hMod, "ProcessNestedSignal");
        } else {
            TrueProcessNestedSignal = nullptr;
        }
    }
    if (!TrueProcessNestedSignal) {
        std::cerr << "[WARNING] Failed to resolve target function: 'ProcessNestedSignal' (check if module is loaded or function is exported)" << std::endl;
    }


    std::vector<HANDLE> threads = EnlistAllThreads();

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    for (HANDLE hThread : threads) {
        DetourUpdateThread(hThread);
    }

    if (TrueParseProprietaryPacket) {
        DetourAttach(&(PVOID&)TrueParseProprietaryPacket, (PVOID)HookedParseProprietaryPacket);
    }
    if (TrueParseProprietaryPacket2) {
        DetourAttach(&(PVOID&)TrueParseProprietaryPacket2, (PVOID)HookedParseProprietaryPacket2);
    }
    if (TrueLogTaskResult) {
        DetourAttach(&(PVOID&)TrueLogTaskResult, (PVOID)HookedLogTaskResult);
    }
    if (TrueProcessCommandSignal) {
        DetourAttach(&(PVOID&)TrueProcessCommandSignal, (PVOID)HookedProcessCommandSignal);
    }
    if (TrueUpdateSensor) {
        DetourAttach(&(PVOID&)TrueUpdateSensor, (PVOID)HookedUpdateSensor);
    }
    if (TrueCalibrateDevice) {
        DetourAttach(&(PVOID&)TrueCalibrateDevice, (PVOID)HookedCalibrateDevice);
    }
    if (TrueProcessDataPoint) {
        DetourAttach(&(PVOID&)TrueProcessDataPoint, (PVOID)HookedProcessDataPoint);
    }
    if (TruePerformCriticalTask) {
        DetourAttach(&(PVOID&)TruePerformCriticalTask, (PVOID)HookedPerformCriticalTask);
    }
    if (TrueProcessNestedSignal) {
        DetourAttach(&(PVOID&)TrueProcessNestedSignal, (PVOID)HookedProcessNestedSignal);
    }


    LONG error = DetourTransactionCommit();

    for (HANDLE hThread : threads) {
        CloseHandle(hThread);
    }

    if (error == NO_ERROR) {
        g_HooksAttached = true;
        std::ostringstream ss;
        ss << "[HOOK] Detours hooks successfully attached. Suspended/resumed " << threads.size() << " worker threads." << std::endl;
        std::cout << ss.str();
    } else {
        std::ostringstream ss;
        ss << "[CRITICAL] DetourTransactionCommit failed. Error code: " << error << std::endl;
        std::cerr << ss.str();
    }
}

extern "C" __declspec(dllexport) void DeinitializeHooks() {
    if (!g_HooksAttached) return;

    std::vector<HANDLE> threads = EnlistAllThreads();

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    for (HANDLE hThread : threads) {
        DetourUpdateThread(hThread);
    }

    if (TrueParseProprietaryPacket) {
        DetourDetach(&(PVOID&)TrueParseProprietaryPacket, (PVOID)HookedParseProprietaryPacket);
    }
    if (TrueParseProprietaryPacket2) {
        DetourDetach(&(PVOID&)TrueParseProprietaryPacket2, (PVOID)HookedParseProprietaryPacket2);
    }
    if (TrueLogTaskResult) {
        DetourDetach(&(PVOID&)TrueLogTaskResult, (PVOID)HookedLogTaskResult);
    }
    if (TrueProcessCommandSignal) {
        DetourDetach(&(PVOID&)TrueProcessCommandSignal, (PVOID)HookedProcessCommandSignal);
    }
    if (TrueUpdateSensor) {
        DetourDetach(&(PVOID&)TrueUpdateSensor, (PVOID)HookedUpdateSensor);
    }
    if (TrueCalibrateDevice) {
        DetourDetach(&(PVOID&)TrueCalibrateDevice, (PVOID)HookedCalibrateDevice);
    }
    if (TrueProcessDataPoint) {
        DetourDetach(&(PVOID&)TrueProcessDataPoint, (PVOID)HookedProcessDataPoint);
    }
    if (TruePerformCriticalTask) {
        DetourDetach(&(PVOID&)TruePerformCriticalTask, (PVOID)HookedPerformCriticalTask);
    }
    if (TrueProcessNestedSignal) {
        DetourDetach(&(PVOID&)TrueProcessNestedSignal, (PVOID)HookedProcessNestedSignal);
    }



    LONG error = DetourTransactionCommit();

    for (HANDLE hThread : threads) {
        CloseHandle(hThread);
    }

    if (error == NO_ERROR) {
        g_HooksAttached = false;
        
        // Spin-wait safety loop for active threads inside hooks
        while (true) {
            while (g_ActiveHooks.load() > 0) {
                SwitchToThread();
            }
            Sleep(1000); 
            if (g_ActiveHooks.load() == 0) {
                break;
            }
        }
        
        std::ostringstream ss;
        ss << "[HOOK] Detours hooks successfully detached." << std::endl;
        std::cout << ss.str();
    } else {
        std::ostringstream ss;
        ss << "[CRITICAL] DetourTransactionCommit failed on detach. Error code: " << error << std::endl;
        std::cerr << ss.str();
    }
}

// DLL Entrypoint
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}