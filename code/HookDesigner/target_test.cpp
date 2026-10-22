#include <windows.h>
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>

static std::mutex g_EngineConsoleMutex;

struct DataPoint {
    int id;
    double value;
};

// Ensure C linkage and exports for hooking resolution
extern "C" {
    __declspec(dllexport) __declspec(noinline) int ParseProprietaryPacket(void* packetBuffer, double complexityWeight) {
        {
            std::lock_guard<std::mutex> lock(g_EngineConsoleMutex);
            std::cout << "[target Engine] ParseProprietaryPacket called: packetBuffer = " << packetBuffer << ", complexityWeight = " << complexityWeight << std::endl;
        }
        if (complexityWeight < 150.0) {
            return 1; // Success/Low load
        }
        return 0; // High load/Failure
    }

    __declspec(dllexport) __declspec(noinline) int ParseProprietaryPacket2(void* packetBuffer, double complexityWeight) {
        {
            std::lock_guard<std::mutex> lock(g_EngineConsoleMutex);
            std::cout << "[target Engine] ParseProprietaryPacket2 called: packetBuffer = " << packetBuffer << ", complexityWeight = " << complexityWeight << std::endl;
        }
        if (complexityWeight < 150.0) {
            return 1; // Success/Low load
        }
        return 0; // High load/Failure
    }

    __declspec(dllexport) __declspec(noinline) void LogTaskResult(int taskId, const char* status, double result) {
        std::lock_guard<std::mutex> lock(g_EngineConsoleMutex);
        std::cout << "[target Engine] LogTaskResult called: taskId = " << taskId 
                  << ", status = " << (status ? status : "null") << ", result = " << result << std::endl;
    }

    __declspec(dllexport) __declspec(noinline) int ProcessCommandSignal(int cmdId, double* payloadValue, char* responseBuffer) {
        {
            std::lock_guard<std::mutex> lock(g_EngineConsoleMutex);
            std::cout << "[target Engine] ProcessCommandSignal called: cmdId = " << cmdId << ", payloadValue = " << (payloadValue ? *payloadValue : 0.0) << ", responseBuffer = " << (responseBuffer ? responseBuffer : "null") << std::endl;
        }
        return 200; // Success code
    }

    __declspec(dllexport) __declspec(noinline) int UpdateSensor(int sensorID, double value) {
        std::lock_guard<std::mutex> lock(g_EngineConsoleMutex);
        std::cout << "[target Engine] UpdateSensor called: sensorID = " << sensorID << ", value = " << value << std::endl;
        return 1;
    }

    __declspec(dllexport) __declspec(noinline) int CalibrateDevice(int deviceID, double offset) {
        std::lock_guard<std::mutex> lock(g_EngineConsoleMutex);
        std::cout << "[target Engine] CalibrateDevice called: deviceID = " << deviceID << ", offset = " << offset << std::endl;
        return 1;
    }

    __declspec(dllexport) __declspec(noinline) int ProcessDataPoint(DataPoint* dp) {
        std::lock_guard<std::mutex> lock(g_EngineConsoleMutex);
        if (dp) {
            std::cout << "[target Engine] ProcessDataPoint called: dp->id = " << dp->id << ", dp->value = " << dp->value << std::endl;
        } else {
            std::cout << "[target Engine] ProcessDataPoint called: dp = null" << std::endl;
        }
        return 1;
    }

    __declspec(dllexport) __declspec(noinline) void WINAPI PerformCriticalTask(int taskID) {
        std::lock_guard<std::mutex> lock(g_EngineConsoleMutex);
        std::cout << "[target Engine] PerformCriticalTask called: taskID = " << taskID << std::endl;
    }

    __declspec(dllexport) __declspec(noinline) int ProcessNestedSignal(double** ppValue) {
        std::lock_guard<std::mutex> lock(g_EngineConsoleMutex);
        if (ppValue && *ppValue) {
            std::cout << "[target Engine] ProcessNestedSignal called: value = " << **ppValue << std::endl;
        } else {
            std::cout << "[target Engine] ProcessNestedSignal called: value = null" << std::endl;
        }
        return 200;
    }
}

std::atomic<bool> g_Running{true};

void WorkerThreadFunc(int id) {
    {
        std::lock_guard<std::mutex> lock(g_EngineConsoleMutex);
        std::cout << "[target Engine] Worker Thread " << id << " started." << std::endl;
    }
    int cycle = 0;
    while (g_Running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
        
        // Vary parameters to trigger behaviors
        double weight = (cycle % 2 == 0) ? 600.0 : 250.0;
        void* dummyBuffer = (void*)(uintptr_t)(0xDEADBEEF + id * 0x1000 + cycle);
        
        ParseProprietaryPacket(dummyBuffer, weight);
        ParseProprietaryPacket2(dummyBuffer, weight);

        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        
        LogTaskResult(id * 100 + cycle, (cycle % 2 == 0) ? "OK" : "WARNING", weight * 1.5);
        
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        
        // Call the third function to test pointers & post-logic mutations
        double payloadVal = (cycle % 2 == 0) ? 1500.0 : 750.0;
        char respBuf[100];
        strcpy_s(respBuf, sizeof(respBuf), "PENDING");
        int ret = ProcessCommandSignal(id * 1000 + cycle, &payloadVal, respBuf);
        {
            std::lock_guard<std::mutex> lock(g_EngineConsoleMutex);
            std::cout << "[target Engine] ProcessCommandSignal returned: " << ret << " | mutated payloadValue: " << payloadVal << " | mutated responseBuffer: " << respBuf << std::endl;
        }

        // Call the new functions for expanded test scenarios
        int sensorID = id * 10;
        double sensorVal = 50.0 + cycle;
        UpdateSensor(sensorID, sensorVal);

        int deviceID = id * 20;
        double deviceOffset = 5.0 + cycle;
        CalibrateDevice(deviceID, deviceOffset);

        DataPoint dp = { id * 30, 12.34 + cycle };
        ProcessDataPoint(&dp);

        PerformCriticalTask(id * 40 + cycle);

        double nestedVal = 100.0 + cycle;
        double* pNestedVal = &nestedVal;
        ProcessNestedSignal(&pNestedVal);

        cycle++;
    }
    {
        std::lock_guard<std::mutex> lock(g_EngineConsoleMutex);
        std::cout << "[target Engine] Worker Thread " << id << " exiting." << std::endl;
    }
}

int main() {
    // Enable console line buffering/flushing
    std::cout.setf(std::ios::unitbuf);

    DWORD pid = GetCurrentProcessId();
    HMODULE hMod = GetModuleHandleA(NULL);
    
    // Resolve addresses dynamically to print RVA offsets
    FARPROC pFuncPacket = GetProcAddress(hMod, "ParseProprietaryPacket");
    FARPROC pFuncPacket2 = GetProcAddress(hMod, "ParseProprietaryPacket2");
    FARPROC pFuncLog = GetProcAddress(hMod, "LogTaskResult");
    FARPROC pFuncCmd = GetProcAddress(hMod, "ProcessCommandSignal");
    FARPROC pFuncUpdateSensor = GetProcAddress(hMod, "UpdateSensor");
    FARPROC pFuncCalibrateDevice = GetProcAddress(hMod, "CalibrateDevice");
    
    uintptr_t rvaPacket = pFuncPacket ? ((uintptr_t)pFuncPacket - (uintptr_t)hMod) : 0;
    uintptr_t rvaPacket2 = pFuncPacket2 ? ((uintptr_t)pFuncPacket2 - (uintptr_t)hMod) : 0;
    uintptr_t rvaCmd = pFuncCmd ? ((uintptr_t)pFuncCmd - (uintptr_t)hMod) : 0;
    uintptr_t rvaUpdateSensor = pFuncUpdateSensor ? ((uintptr_t)pFuncUpdateSensor - (uintptr_t)hMod) : 0;
    uintptr_t rvaCalibrateDevice = pFuncCalibrateDevice ? ((uintptr_t)pFuncCalibrateDevice - (uintptr_t)hMod) : 0;

    std::cout << "=== target ENGINE SIMULATOR ===" << std::endl;
    std::cout << "PID: " << pid << std::endl;
    std::cout << "Base Address: " << hMod << std::endl;
    std::cout << "ParseProprietaryPacket Address: " << (void*)pFuncPacket << std::endl;
    std::cout << "ParseProprietaryPacket RVA Offset: 0x" << std::hex << rvaPacket << std::dec << std::endl;
    std::cout << "ParseProprietaryPacket2 Address: " << (void*)pFuncPacket2 << std::endl;
    std::cout << "ParseProprietaryPacket2 RVA Offset: 0x" << std::hex << rvaPacket2 << std::dec << std::endl;
    std::cout << "ProcessCommandSignal Address: " << (void*)pFuncCmd << std::endl;
    std::cout << "ProcessCommandSignal RVA Offset: 0x" << std::hex << rvaCmd << std::dec << std::endl;
    std::cout << "UpdateSensor Address: " << (void*)pFuncUpdateSensor << std::endl;
    std::cout << "UpdateSensor RVA Offset: 0x" << std::hex << rvaUpdateSensor << std::dec << std::endl;
    std::cout << "CalibrateDevice Address: " << (void*)pFuncCalibrateDevice << std::endl;
    std::cout << "CalibrateDevice RVA Offset: 0x" << std::hex << rvaCalibrateDevice << std::dec << std::endl;
    std::cout << "==============================" << std::endl;
    std::cout.flush();

    // Launch worker threads
    const int numThreads = 3;
    std::vector<std::thread> threads;
    for (int i = 0; i < numThreads; i++) {
        threads.emplace_back(WorkerThreadFunc, i + 1);
    }

    // Wait for enter to exit key or signal
    std::cout << "Press ENTER to terminate the engine." << std::endl;
    std::cin.get();

    g_Running.store(false);
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    std::cout << "[target Engine] Shutdown complete." << std::endl;
    return 0;
}
