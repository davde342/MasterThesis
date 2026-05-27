//AI generated: dummy multithreaded task queue simulator, for testing more complex scenario
// (see code\first_examples\hook_detours_mt.cpp and code\first_examples\hook_gum_dll_mt.cpp)
#include <windows.h>
#include <iostream>
#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <string>
#include <chrono>

struct Task {
    int id;
    std::string type;
    int complexity; // simulated milliseconds to process
};

// Global queue variables 
std::queue<Task> g_Queue;
std::mutex g_QueueMutex;
std::condition_variable g_QueueCv;
bool g_QueueShutdown = false;
bool g_Running = true;

// Global console mutex to synchronize target prints
std::mutex g_ConsoleMutex;

// Queue manipulation functions
void QueuePush(Task task) {
    std::lock_guard<std::mutex> lock(g_QueueMutex);
    g_Queue.push(task);
    g_QueueCv.notify_one();
}

bool QueuePop(Task& task) {
    std::unique_lock<std::mutex> lock(g_QueueMutex);
    g_QueueCv.wait(lock, []() { return !g_Queue.empty() || g_QueueShutdown; });
    if (g_Queue.empty()) {
        return false;
    }
    task = g_Queue.front();
    g_Queue.pop();
    return true;
}

void QueueShutdown() {
    std::lock_guard<std::mutex> lock(g_QueueMutex);
    g_QueueShutdown = true;
    g_QueueCv.notify_all();
}

// -------------------------------------------------------------------------
// EXPORTED FUNCTIONS
// These functions are exported from the EXE so the hook DLL can detour them.
// -------------------------------------------------------------------------

extern "C" __declspec(dllexport) void ProcessTask(int taskId, const char* taskType, int complexity) {
    {
        std::lock_guard<std::mutex> lock(g_ConsoleMutex);
        std::cout << "[TARGET] Processing Task ID: " << taskId 
                  << " | Type: " << taskType 
                  << " | Complexity: " << complexity << "ms" << std::endl;
    }

    // Simulate work by sleeping
    Sleep(static_cast<DWORD>(complexity));
}

extern "C" __declspec(dllexport) void LogTaskResult(int taskId, const char* status, double result) {
    {
        std::lock_guard<std::mutex> lock(g_ConsoleMutex);
        std::cout << "[TARGET] Finished Task ID: " << taskId 
                  << " | Status: " << status 
                  << " | Result: " << result << std::endl << std::endl;
    }
}

// -------------------------------------------------------------------------
// WORKER THREAD FUNCTION
// -------------------------------------------------------------------------

void WorkerThreadFunc(int workerId) {
    DWORD threadId = GetCurrentThreadId();
    {
        std::lock_guard<std::mutex> lock(g_ConsoleMutex);
        std::cout << "[Worker " << workerId << "] Started (System TID: " << threadId << ")" << std::endl;
    }

    Task task;
    while (g_Running && QueuePop(task)) {
        ProcessTask(task.id, task.type.c_str(), task.complexity);

        double computedResult = 0.0;
        if (task.type == "COMPUTE") {
            computedResult = task.complexity * 3.14159;
        } else if (task.type == "ENCRYPT") {
            computedResult = (task.complexity ^ 0xAA) / 2.0;
        } else {
            computedResult = task.complexity + 42.0;
        }

        LogTaskResult(task.id, "COMPLETED", computedResult);
    }

    {
        std::lock_guard<std::mutex> lock(g_ConsoleMutex);
        std::cout << "[Worker " << workerId << "] Exiting..." << std::endl;
    }
}

// -------------------------------------------------------------------------
// PRODUCER THREAD FUNCTION
// -------------------------------------------------------------------------

void ProducerThreadFunc() {
    int taskId = 0;
    const std::string taskTypes[] = { "COMPUTE", "ENCRYPT", "IO_WRITE" };
    
    while (g_Running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        
        Task t;
        t.id = ++taskId;
        t.type = taskTypes[taskId % 3];
        t.complexity = (taskId % 2 == 0) ? 800 : 200; // 800ms vs 200ms

        QueuePush(t);
    }
}

// -------------------------------------------------------------------------
// MAIN / ENTRY
// -------------------------------------------------------------------------

int main() {
    {
        std::lock_guard<std::mutex> lock(g_ConsoleMutex);
        std::cout << "========================================================\n";
        std::cout << "      GENERIC MULTITHREADED TASK QUEUE PROCESSOR        \n";
        std::cout << "      Process PID: " << GetCurrentProcessId() << "\n";
        std::cout << "========================================================\n";
        std::cout << "Press ENTER to spawn worker threads and start producing tasks...\n";
    }
    std::cin.get();

    // Spawn 3 worker threads
    const int numWorkers = 3;
    std::vector<std::thread> workers;
    for (int i = 0; i < numWorkers; ++i) {
        workers.push_back(std::thread(WorkerThreadFunc, i + 1));
    }

    {
        std::lock_guard<std::mutex> lock(g_ConsoleMutex);
        std::cout << "\nWorkers spawned and running. You can inject the hook DLL at any time.\n";
        std::cout << "Press ENTER again to stop the program.\n\n";
    }

    // Spawn producer thread
    std::thread producer(ProducerThreadFunc);

    // Wait for operator to signal exit
    std::cin.get();
    {
        std::lock_guard<std::mutex> lock(g_ConsoleMutex);
        std::cout << "Shutting down..." << std::endl;
    }

    // Shutdown queue and threads
    g_Running = false;
    QueueShutdown();

    producer.join();
    for (auto& w : workers) {
        w.join();
    }

    {
        std::lock_guard<std::mutex> lock(g_ConsoleMutex);
        std::cout << "Program exited cleanly." << std::endl;
    }
    return 0;
}
