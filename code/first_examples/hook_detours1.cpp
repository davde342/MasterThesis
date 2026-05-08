#include <windows.h>
#include <detours.h>
#include <iostream>

/*  From the microsoft docs: If the DLL may be used in mixed 32-bit and 64-bit environments, 
    then the DllMain function must call the DetourIsHelperProcess API. The DLL must export
    the DetourFinishHelperProcess API as export Ordinal 1,
    which will be called by rundll32.exe to perform the helper tasks.
*/
#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:DetourFinishHelperProcess=_DetourFinishHelperProcess@16,@1,NONAME")
#else 
#pragma comment(linker, "/EXPORT:DetourFinishHelperProcess=DetourFinishHelperProcess,@1,NONAME")
#endif

// function pointer to the original function 
static int (WINAPI * TrueMessageBoxW)(HWND, LPCWSTR, LPCWSTR, UINT) = MessageBoxW;

// Hook
int WINAPI HookedMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    
    //PRE-LOGIC
    
    UINT modifiedType = MB_YESNO;
    LPCWSTR customCaption = L"Hooked! Please choose:";

    // Call the original function
    int result = TrueMessageBoxW(hWnd, lpText, customCaption, modifiedType);

    // POST-LOGIC

    if (result == IDNO) 
    {
        std::cout << "[HOOK POST-LOGIC] Intercepted IDNO (No). Changing result to IDYES (Yes)!" << std::endl;

        result = IDYES; 
    }
    else if (result == IDYES)
    {
        std::cout << "[HOOK POST-LOGIC] Intercepted IDYES (Yes). Nothing to do" << std::endl;
    }

    return result;
}

// DLL Entry Point   
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    }
    if (dwReason == DLL_PROCESS_ATTACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueMessageBoxW, HookedMessageBoxW);
        DetourTransactionCommit();
    } else if (dwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueMessageBoxW, HookedMessageBoxW);
        DetourTransactionCommit();
    }
    return TRUE;
}