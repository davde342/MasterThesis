#include <windows.h>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: injector.exe <PID> <Absolute_Path_To_DLL>\n";
        return 1;
    }

    DWORD pid = std::stoi(argv[1]);
    std::string dllPath = argv[2];

    // Open the target process with necessary permissions
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << "\n";
        return 1;
    }

    // Allocate memory inside the target process for the DLL path string
    LPVOID pRemoteString = VirtualAllocEx(hProcess, NULL, dllPath.length() + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteString) {
        std::cerr << "Failed to allocate memory in target process.\n";
        CloseHandle(hProcess);
        return 1;
    }

    // Write the DLL path string
    WriteProcessMemory(hProcess, pRemoteString, (LPVOID)dllPath.c_str(), dllPath.length() + 1, NULL);

    HMODULE hKernel32 = GetModuleHandleA("Kernel32.dll");
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");

    // Create a thread in the target process that starts at LoadLibraryA and passes the string as its argument
    std::cout << "Injecting DLL\n";
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteString, 0, NULL);
    
    if (!hThread) {
        std::cerr << "Failed to create remote thread. Error: " << GetLastError() << "\n";
    } else {
        std::cout << "Injection successful\n";
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    VirtualFreeEx(hProcess, pRemoteString, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}
