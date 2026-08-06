#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
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
            if (_stricmp(me.szModule, moduleName) == 0) {
                hModule = (HMODULE)me.modBaseAddr;
                break;
            }
        } while (Module32Next(hSnapshot, &me));
    }
    CloseHandle(hSnapshot);
    return hModule;
}

//helper: extract the raw filename from a full file path
std::string GetFilename(const std::string& path) {
    size_t lastSlash = path.find_last_of("\\/");
    if (lastSlash == std::string::npos) { //it means no slash was found, so the path is already the filename
        return path;
    }
    return path.substr(lastSlash + 1);
}

bool CallRemoteExport(HANDLE hProcess, HMODULE hRemoteModule, const std::string& localDllPath, const std::string& exportName, DWORD* outExitCode = nullptr) {
    HMODULE hLocalMod = LoadLibraryExA(localDllPath.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hLocalMod) {
        std::cerr << "Error: Failed to load DLL \"" << localDllPath << "\" locally. Error: " << GetLastError() << "\n";
        return false;
    }

    FARPROC pLocalFunc = GetProcAddress(hLocalMod, exportName.c_str());
    if (!pLocalFunc) {
        std::cerr << "Error: Export \"" << exportName << "\" not found in DLL.\n";
        FreeLibrary(hLocalMod);
        return false;
    }

    DWORD_PTR offset = (DWORD_PTR)pLocalFunc - (DWORD_PTR)hLocalMod;
    LPVOID pRemoteFunc = (LPVOID)((DWORD_PTR)hRemoteModule + offset);
    FreeLibrary(hLocalMod);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteFunc, NULL, 0, NULL);
    if (!hThread) {
        std::cerr << "Error: Failed to execute remote thread for export \"" << exportName << "\". Error: " << GetLastError() << "\n";
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    if (outExitCode) {
        GetExitCodeThread(hThread, outExitCode);
    }
    CloseHandle(hThread);
    return true;
}

HMODULE GetAndValidateDllBase(DWORD pid, const std::string& dllPath) {
    std::string filename = GetFilename(dllPath);
    HMODULE hRemoteModule = GetDllBase(pid, filename.c_str());
    if (!hRemoteModule) {
        std::cerr << "Failed to find base address of module \"" << filename << "\" in target process.\n";
    }
    return hRemoteModule;
}

bool InjectDll(HANDLE hProcess, const std::string& dllPath) {
    LPVOID pRemoteString = VirtualAllocEx(hProcess, NULL, dllPath.length() + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteString) {
        std::cerr << "Failed to allocate memory in target process. Error: " << GetLastError() << "\n";
        return false;
    }

    if (!WriteProcessMemory(hProcess, pRemoteString, (LPVOID)dllPath.c_str(), dllPath.length() + 1, NULL)) {
        std::cerr << "Failed to write DLL path to target process memory. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, pRemoteString, 0, MEM_RELEASE);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleA("Kernel32.dll");
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteString, 0, NULL);
    if (!hThread) {
        std::cerr << "Failed to create remote thread. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, pRemoteString, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    DWORD threadExitCode = 0;
    BOOL gotExit = GetExitCodeThread(hThread, &threadExitCode);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteString, 0, MEM_RELEASE);

    if (gotExit && threadExitCode == 0) {
        std::cerr << "LoadLibraryA failed in the target process. DLL might be invalid or missing dependencies.\n";
        return false;
    }

    return true;
}

bool ResolveAndValidateDll(std::string& dllPath) {
    char fullPath[MAX_PATH];
    DWORD retval = GetFullPathNameA(dllPath.c_str(), MAX_PATH, fullPath, nullptr);
    if (retval == 0) {
        std::cerr << "Error: Failed to resolve absolute path for DLL \"" << dllPath << "\". Error: " << GetLastError() << "\n";
        return false;
    }
    dllPath = fullPath;

    DWORD dwAttrib = GetFileAttributesA(dllPath.c_str());
    if (dwAttrib == INVALID_FILE_ATTRIBUTES || (dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
        std::cerr << "Error: DLL file \"" << dllPath << "\" does not exist or is not accessible.\n";
        return false;
    }
    return true;
}

int main(int argc, char* argv[]) {
    std::string mode = "inject";
    DWORD pid = 0;
    std::string dllPath;

    auto printUsage = []() {
        std::cout << "Usage:\n";
        std::cout << "  injector.exe <PID> <Path_To_DLL>  (default: inject)\n";
        std::cout << "  injector.exe inject <PID> <Path_To_DLL> (relative or absolute)\n";
        std::cout << "  injector.exe eject <PID> <Path_To_DLL> (relative or absolute)\n";
        std::cout << "  injector.exe launch <Executable_Path> <Path_To_DLL> (relative or absolute) [optional_target_args]\n";
    };

    if (argc < 2) {
        printUsage();
        return 1;
    }

    std::string arg1 = argv[1];

    if (arg1 == "launch") {
        if (argc < 4) {
            std::cerr << "Error: 'launch' mode requires an executable path and a DLL path.\n";
            printUsage();
            return 1;
        }
        mode = "launch";
        dllPath = argv[3];
    } else if (arg1 == "inject" || arg1 == "eject") {
        if (argc != 4) {
            std::cerr << "Error: '" << arg1 << "' mode requires exactly a PID and a DLL path/name.\n";
            printUsage();
            return 1;
        }
        mode = arg1;
        try {
            pid = std::stoi(argv[2]);
        } catch (const std::exception& e) {
            std::cerr << "Error: Invalid PID \"" << argv[2] << "\" (" << e.what() << ")\n";
            return 1;
        }
        dllPath = argv[3];
    } else {
        // Assume default "inject" mode
        if (argc != 3) {
            std::cerr << "Error: Invalid arguments.\n";
            printUsage();
            return 1;
        }
        mode = "inject";
        try {
            pid = std::stoi(argv[1]);
        } catch (const std::exception& e) {
            std::cerr << "Error: Invalid PID \"" << argv[1] << "\" (" << e.what() << ")\n";
            return 1;
        }
        dllPath = argv[2];
    }

   
    if (!ResolveAndValidateDll(dllPath)) {
        return 1;
    }

    if (mode == "launch") {
        std::string exePath = argv[2];
        
        std::string cmdLine = "\"" + exePath + "\"";
        for (int i = 4; i < argc; ++i) {
            cmdLine += " ";
            cmdLine += argv[i];
        }

        std::vector<char> cmdBuffer(cmdLine.begin(), cmdLine.end());
        cmdBuffer.push_back('\0');

        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        std::cout << "Launching target process in suspended state...\n";
        BOOL success = CreateProcessA(
            exePath.c_str(),
            cmdBuffer.data(),
            NULL,
            NULL,
            TRUE,
            CREATE_SUSPENDED,
            NULL,
            NULL,
            &si,
            &pi
        );

        if (!success) {
            std::cerr << "Failed to launch process. Error: " << GetLastError() << "\n";
            return 1;
        }

        std::cout << "Successfully launched process suspended. PID: " << pi.dwProcessId << "\n";

        std::cout << "Injecting DLL into suspended process\n";
        if (!InjectDll(pi.hProcess, dllPath)) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return 1;
        }

        std::cout << "Injection successful. Calling InitializeHooks\n";
        HMODULE hRemoteModule = GetAndValidateDllBase(pi.dwProcessId, dllPath);
        if (!hRemoteModule || !CallRemoteExport(pi.hProcess, hRemoteModule, dllPath, "InitializeHooks")) {
            std::cerr << "Failed to call InitializeHooks\n";
        }

        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);

        std::cout << "Process resumed\n";
        WaitForSingleObject(pi.hProcess, INFINITE);

        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);

        std::cout << "Process exited with code: " << exitCode << "\n";
        return (int)exitCode;
    }

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << "\n";
        return 1;
    }

    if (mode == "inject") {

        std::cout << "Injecting DLL\n";
        if (!InjectDll(hProcess, dllPath)) {
            CloseHandle(hProcess);
            return 1;
        }

        std::cout << "Injection successful. Calling InitializeHooks\n";
        HMODULE hRemoteModule = GetAndValidateDllBase(pid, dllPath);
        if (!hRemoteModule || !CallRemoteExport(hProcess, hRemoteModule, dllPath, "InitializeHooks")) {
            std::cerr << "Failed to call InitializeHooks remotely.\n";
        }
    } else if (mode == "eject") {
        HMODULE hRemoteModule = GetAndValidateDllBase(pid, dllPath);
        if (!hRemoteModule) {
            CloseHandle(hProcess);
            return 1;
        }

        HMODULE hKernel32 = GetModuleHandleA("Kernel32.dll");
        LPVOID pFreeLibrary = (LPVOID)GetProcAddress(hKernel32, "FreeLibrary");

        std::cout << "Calling DeinitializeHooks remotely...\n";
        DWORD deinitExitCode = 1; // Default to success/TRUE
        if (!CallRemoteExport(hProcess, hRemoteModule, dllPath, "DeinitializeHooks", &deinitExitCode)) {
            std::cerr << "Warning: Failed to call DeinitializeHooks remotely.\n";
        }

        if (deinitExitCode == 0) { // FALSE
            std::cout << "[WARNING] Hooks successfully detached, but some threads remain blocked inside them, frequent when blocking functions are hooked.\n";
            std::cout << "[WARNING] Skipping FreeLibrary (leaking DLL in target memory) to prevent target crash. Ejection completed.\n";
        } else {
            std::cout << "Ejecting DLL...\n";
            HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFreeLibrary, (LPVOID)hRemoteModule, 0, NULL);
            if (!hThread) {
                std::cerr << "Failed to create remote thread. Error: " << GetLastError() << "\n";
            } else {
                WaitForSingleObject(hThread, INFINITE);
                std::cout << "Ejection successful\n";
                CloseHandle(hThread);
            }
        }
    }
    CloseHandle(hProcess);
    return 0;
}
