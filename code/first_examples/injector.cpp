#include <windows.h>
#include <iostream>
#include <string>
#include <tlhelp32.h>

HMODULE GetDllBase(DWORD pid, const char* moduleName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    HMODULE hModule = NULL;
    if (Module32First(hSnapshot, &me)) {
        do {
            // me.szModule contains only the filename, not the absolute path.
            if (_stricmp(me.szModule, moduleName) == 0) {
                hModule = (HMODULE)me.modBaseAddr;
                break;
            }
        } while (Module32Next(hSnapshot, &me));
    }
    CloseHandle(hSnapshot);
    return hModule;
}

int main(int argc, char* argv[]) {
    std::string mode = "inject";
    DWORD pid = 0;
    std::string dllPathOrName;

    if (argc == 3) {
        pid = std::stoi(argv[1]);
        dllPathOrName = argv[2];
    } else if (argc == 4) {
        mode = argv[1];
        pid = std::stoi(argv[2]);
        dllPathOrName = argv[3];
    } else {
        std::cout << "Usage:\n";
        std::cout << "  injector.exe <PID> <Absolute_Path_To_DLL>  (default: inject)\n";
        std::cout << "  injector.exe inject <PID> <Absolute_Path_To_DLL>\n";
        std::cout << "  injector.exe eject <PID> <DLL_Name>\n";
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << "\n";
        return 1;
    }

    if (mode == "inject") {
        LPVOID pRemoteString = VirtualAllocEx(hProcess, NULL, dllPathOrName.length() + 1, MEM_COMMIT, PAGE_READWRITE);
        if (!pRemoteString) {
            std::cerr << "Failed to allocate memory in target process.\n";
            CloseHandle(hProcess);
            return 1;
        }

        WriteProcessMemory(hProcess, pRemoteString, (LPVOID)dllPathOrName.c_str(), dllPathOrName.length() + 1, NULL);

        HMODULE hKernel32 = GetModuleHandleA("Kernel32.dll");
        LPVOID pLoadLibrary = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");

        std::cout << "Injecting DLL...\n";
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteString, 0, NULL);
        if (!hThread) {
            std::cerr << "Failed to create remote thread. Error: " << GetLastError() << "\n";
        } else {
            std::cout << "Injection successful\n";
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }

        VirtualFreeEx(hProcess, pRemoteString, 0, MEM_RELEASE);
    } else if (mode == "eject") {
        HMODULE hRemoteModule = GetDllBase(pid, dllPathOrName.c_str());
        if (!hRemoteModule) {
            std::cerr << "Failed to find module \"" << dllPathOrName << "\" in target process.\n";
            CloseHandle(hProcess);
            return 1;
        }

        HMODULE hKernel32 = GetModuleHandleA("Kernel32.dll");
        LPVOID pFreeLibrary = (LPVOID)GetProcAddress(hKernel32, "FreeLibrary");

        std::cout << "Ejecting DLL...\n";
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFreeLibrary, (LPVOID)hRemoteModule, 0, NULL);
        if (!hThread) {
            std::cerr << "Failed to create remote thread. Error: " << GetLastError() << "\n";
        } else {
            std::cout << "Ejection successful\n";
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
    } else {
        std::cerr << "Unknown mode: " << mode << "\n";
    }

    CloseHandle(hProcess);
    return 0;
}
