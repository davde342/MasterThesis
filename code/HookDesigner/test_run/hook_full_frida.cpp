#include "frida-gum.h"
#include <windows.h>
#include <iostream>
#include <sstream>
#include <mutex>
#include <atomic>
#include <vector>
#include <string>


static bool g_HooksAttached = false;
static GumInterceptor* interceptor = nullptr;
static LARGE_INTEGER g_PerfFrequency = {0};

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



// Target functions typedefs, pointers, and entry points
typedef int (*TrueParseProprietaryPacket_t)(void * packetBuffer,double complexityWeight);
static TrueParseProprietaryPacket_t TrueParseProprietaryPacket = nullptr;
static gpointer target_ParseProprietaryPacket = nullptr;
typedef int (*TrueParseProprietaryPacket2_t)(void * packetBuffer,double complexityWeight);
static TrueParseProprietaryPacket2_t TrueParseProprietaryPacket2 = nullptr;
static gpointer target_ParseProprietaryPacket2 = nullptr;
typedef void (*TrueLogTaskResult_t)(int taskId,const char * status,double result);
static TrueLogTaskResult_t TrueLogTaskResult = nullptr;
static gpointer target_LogTaskResult = nullptr;
typedef int (*TrueProcessCommandSignal_t)(int cmdId,double * payloadValue,char * responseBuffer);
static TrueProcessCommandSignal_t TrueProcessCommandSignal = nullptr;
static gpointer target_ProcessCommandSignal = nullptr;
typedef int (*TrueUpdateSensor_t)(int id,double val);
static TrueUpdateSensor_t TrueUpdateSensor = nullptr;
static gpointer target_UpdateSensor = nullptr;
typedef int (*TrueCalibrateDevice_t)(int id,double val);
static TrueCalibrateDevice_t TrueCalibrateDevice = nullptr;
static gpointer target_CalibrateDevice = nullptr;
typedef int (*TrueProcessDataPoint_t)(DataPoint * dp);
static TrueProcessDataPoint_t TrueProcessDataPoint = nullptr;
static gpointer target_ProcessDataPoint = nullptr;
typedef void (WINAPI *TruePerformCriticalTask_t)(int taskID);
static TruePerformCriticalTask_t TruePerformCriticalTask = nullptr;
static gpointer target_PerformCriticalTask = nullptr;
typedef int (*TrueProcessNestedSignal_t)(double ** ppValue);
static TrueProcessNestedSignal_t TrueProcessNestedSignal = nullptr;
static gpointer target_ProcessNestedSignal = nullptr;

// Hook Implementations
int HookedParseProprietaryPacket(void * packetBuffer,double complexityWeight) {


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
    gum_init_embedded();
    interceptor = gum_interceptor_obtain();

    {
        HMODULE hMod = GetModuleHandleA("scada_engine.exe");
        if (hMod) {
            target_ParseProprietaryPacket = (gpointer)((char*)hMod + 0x1000);
        } else {
            target_ParseProprietaryPacket = nullptr;
        }
    }
    if (!target_ParseProprietaryPacket) {
        std::cerr << "[WARNING] Failed to resolve target function: 'ParseProprietaryPacket' (check if module is loaded or function is exported)" << std::endl;
    }
    {
        HMODULE hMod = GetModuleHandleA("scada_engine.exe");
        if (hMod) {
            target_ParseProprietaryPacket2 = (gpointer)((char*)hMod + 0x1000);
        } else {
            target_ParseProprietaryPacket2 = nullptr;
        }
    }
    if (!target_ParseProprietaryPacket2) {
        std::cerr << "[WARNING] Failed to resolve target function: 'ParseProprietaryPacket2' (check if module is loaded or function is exported)" << std::endl;
    }
    {
        HMODULE hMod = GetModuleHandleA("scada_engine.exe");
        if (hMod) {
            target_LogTaskResult = (gpointer)GetProcAddress(hMod, "LogTaskResult");
        } else {
            target_LogTaskResult = nullptr;
        }
    }
    if (!target_LogTaskResult) {
        std::cerr << "[WARNING] Failed to resolve target function: 'LogTaskResult' (check if module is loaded or function is exported)" << std::endl;
    }
    {
        HMODULE hMod = GetModuleHandleA("scada_engine.exe");
        if (hMod) {
            target_ProcessCommandSignal = (gpointer)GetProcAddress(hMod, "ProcessCommandSignal");
        } else {
            target_ProcessCommandSignal = nullptr;
        }
    }
    if (!target_ProcessCommandSignal) {
        std::cerr << "[WARNING] Failed to resolve target function: 'ProcessCommandSignal' (check if module is loaded or function is exported)" << std::endl;
    }
    {
        HMODULE hMod = GetModuleHandleA("scada_engine.exe");
        if (hMod) {
            target_UpdateSensor = (gpointer)((char*)hMod + 0x1000);
        } else {
            target_UpdateSensor = nullptr;
        }
    }
    if (!target_UpdateSensor) {
        std::cerr << "[WARNING] Failed to resolve target function: 'UpdateSensor' (check if module is loaded or function is exported)" << std::endl;
    }
    {
        HMODULE hMod = GetModuleHandleA("scada_engine.exe");
        if (hMod) {
            target_CalibrateDevice = (gpointer)((char*)hMod + 0x1000);
        } else {
            target_CalibrateDevice = nullptr;
        }
    }
    if (!target_CalibrateDevice) {
        std::cerr << "[WARNING] Failed to resolve target function: 'CalibrateDevice' (check if module is loaded or function is exported)" << std::endl;
    }
    {
        HMODULE hMod = GetModuleHandleA("scada_engine.exe");
        if (hMod) {
            target_ProcessDataPoint = (gpointer)GetProcAddress(hMod, "ProcessDataPoint");
        } else {
            target_ProcessDataPoint = nullptr;
        }
    }
    if (!target_ProcessDataPoint) {
        std::cerr << "[WARNING] Failed to resolve target function: 'ProcessDataPoint' (check if module is loaded or function is exported)" << std::endl;
    }
    {
        HMODULE hMod = GetModuleHandleA("scada_engine.exe");
        if (hMod) {
            target_PerformCriticalTask = (gpointer)GetProcAddress(hMod, "PerformCriticalTask");
        } else {
            target_PerformCriticalTask = nullptr;
        }
    }
    if (!target_PerformCriticalTask) {
        std::cerr << "[WARNING] Failed to resolve target function: 'PerformCriticalTask' (check if module is loaded or function is exported)" << std::endl;
    }
    {
        HMODULE hMod = GetModuleHandleA("scada_engine.exe");
        if (hMod) {
            target_ProcessNestedSignal = (gpointer)GetProcAddress(hMod, "ProcessNestedSignal");
        } else {
            target_ProcessNestedSignal = nullptr;
        }
    }
    if (!target_ProcessNestedSignal) {
        std::cerr << "[WARNING] Failed to resolve target function: 'ProcessNestedSignal' (check if module is loaded or function is exported)" << std::endl;
    }


    gum_interceptor_begin_transaction(interceptor);

    if (target_ParseProprietaryPacket) {
        GumReplaceReturn r = gum_interceptor_replace(interceptor,
                                target_ParseProprietaryPacket,
                                (gpointer)HookedParseProprietaryPacket,
                                nullptr,
                                (gpointer*)&TrueParseProprietaryPacket);
        if (r != GUM_REPLACE_OK) {
            std::cerr << "[CRITICAL] Frida failed to replace function 'ParseProprietaryPacket'. Error code: " << r << std::endl;
        }
    }
    if (target_ParseProprietaryPacket2) {
        GumReplaceReturn r = gum_interceptor_replace(interceptor,
                                target_ParseProprietaryPacket2,
                                (gpointer)HookedParseProprietaryPacket2,
                                nullptr,
                                (gpointer*)&TrueParseProprietaryPacket2);
        if (r != GUM_REPLACE_OK) {
            std::cerr << "[CRITICAL] Frida failed to replace function 'ParseProprietaryPacket2'. Error code: " << r << std::endl;
        }
    }
    if (target_LogTaskResult) {
        GumReplaceReturn r = gum_interceptor_replace(interceptor,
                                target_LogTaskResult,
                                (gpointer)HookedLogTaskResult,
                                nullptr,
                                (gpointer*)&TrueLogTaskResult);
        if (r != GUM_REPLACE_OK) {
            std::cerr << "[CRITICAL] Frida failed to replace function 'LogTaskResult'. Error code: " << r << std::endl;
        }
    }
    if (target_ProcessCommandSignal) {
        GumReplaceReturn r = gum_interceptor_replace(interceptor,
                                target_ProcessCommandSignal,
                                (gpointer)HookedProcessCommandSignal,
                                nullptr,
                                (gpointer*)&TrueProcessCommandSignal);
        if (r != GUM_REPLACE_OK) {
            std::cerr << "[CRITICAL] Frida failed to replace function 'ProcessCommandSignal'. Error code: " << r << std::endl;
        }
    }
    if (target_UpdateSensor) {
        GumReplaceReturn r = gum_interceptor_replace(interceptor,
                                target_UpdateSensor,
                                (gpointer)HookedUpdateSensor,
                                nullptr,
                                (gpointer*)&TrueUpdateSensor);
        if (r != GUM_REPLACE_OK) {
            std::cerr << "[CRITICAL] Frida failed to replace function 'UpdateSensor'. Error code: " << r << std::endl;
        }
    }
    if (target_CalibrateDevice) {
        GumReplaceReturn r = gum_interceptor_replace(interceptor,
                                target_CalibrateDevice,
                                (gpointer)HookedCalibrateDevice,
                                nullptr,
                                (gpointer*)&TrueCalibrateDevice);
        if (r != GUM_REPLACE_OK) {
            std::cerr << "[CRITICAL] Frida failed to replace function 'CalibrateDevice'. Error code: " << r << std::endl;
        }
    }
    if (target_ProcessDataPoint) {
        GumReplaceReturn r = gum_interceptor_replace(interceptor,
                                target_ProcessDataPoint,
                                (gpointer)HookedProcessDataPoint,
                                nullptr,
                                (gpointer*)&TrueProcessDataPoint);
        if (r != GUM_REPLACE_OK) {
            std::cerr << "[CRITICAL] Frida failed to replace function 'ProcessDataPoint'. Error code: " << r << std::endl;
        }
    }
    if (target_PerformCriticalTask) {
        GumReplaceReturn r = gum_interceptor_replace(interceptor,
                                target_PerformCriticalTask,
                                (gpointer)HookedPerformCriticalTask,
                                nullptr,
                                (gpointer*)&TruePerformCriticalTask);
        if (r != GUM_REPLACE_OK) {
            std::cerr << "[CRITICAL] Frida failed to replace function 'PerformCriticalTask'. Error code: " << r << std::endl;
        }
    }
    if (target_ProcessNestedSignal) {
        GumReplaceReturn r = gum_interceptor_replace(interceptor,
                                target_ProcessNestedSignal,
                                (gpointer)HookedProcessNestedSignal,
                                nullptr,
                                (gpointer*)&TrueProcessNestedSignal);
        if (r != GUM_REPLACE_OK) {
            std::cerr << "[CRITICAL] Frida failed to replace function 'ProcessNestedSignal'. Error code: " << r << std::endl;
        }
    }


    gum_interceptor_end_transaction(interceptor);

    g_HooksAttached = true;
    std::ostringstream ss;
    ss << "[HOOK] Frida-Gum hooks successfully attached." << std::endl;
    std::cout << ss.str();
}

extern "C" __declspec(dllexport) void DeinitializeHooks() {
    if (!g_HooksAttached) return;

    gum_interceptor_begin_transaction(interceptor);
    if (target_ParseProprietaryPacket != nullptr) {
        gum_interceptor_revert(interceptor, target_ParseProprietaryPacket);
    }
    if (target_ParseProprietaryPacket2 != nullptr) {
        gum_interceptor_revert(interceptor, target_ParseProprietaryPacket2);
    }
    if (target_LogTaskResult != nullptr) {
        gum_interceptor_revert(interceptor, target_LogTaskResult);
    }
    if (target_ProcessCommandSignal != nullptr) {
        gum_interceptor_revert(interceptor, target_ProcessCommandSignal);
    }
    if (target_UpdateSensor != nullptr) {
        gum_interceptor_revert(interceptor, target_UpdateSensor);
    }
    if (target_CalibrateDevice != nullptr) {
        gum_interceptor_revert(interceptor, target_CalibrateDevice);
    }
    if (target_ProcessDataPoint != nullptr) {
        gum_interceptor_revert(interceptor, target_ProcessDataPoint);
    }
    if (target_PerformCriticalTask != nullptr) {
        gum_interceptor_revert(interceptor, target_PerformCriticalTask);
    }
    if (target_ProcessNestedSignal != nullptr) {
        gum_interceptor_revert(interceptor, target_ProcessNestedSignal);
    }


    gum_interceptor_end_transaction(interceptor);

    while (!gum_interceptor_flush(interceptor)) {
        SwitchToThread ();
    }

    g_object_unref(interceptor);
    gum_deinit_embedded();
    g_HooksAttached = false;

    std::ostringstream ss;
    ss << "[HOOK] Frida-Gum hooks successfully detached." << std::endl;
    std::cout << ss.str();
}

// DLL Entrypoint
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {

    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}