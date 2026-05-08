#include <windows.h>
#include <MinHook.h>
#include <iostream>

//Target Function pointer
typedef int (WINAPI * MESSAGEBOXW)(HWND, LPCWSTR, LPCWSTR, UINT);
MESSAGEBOXW fpMessageBoxW = NULL;

//Hook Function
int WINAPI HookedMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    //Pre-logic
    UINT modifiedType = MB_YESNO;
    LPCWSTR customCaption = L"Hooked, choose:";

    //Call the original function
    int result = fpMessageBoxW(hWnd, lpText, customCaption, modifiedType);

    //Post-logic
    if (result == IDNO) 
    {
        std::cout << "Intercepted IDNO (No). Changing result to IDYES (Yes)!" << std::endl;
        result = IDYES; 
    }
    else if (result == IDYES)
    {
        std::cout << "Intercepted IDYES (Yes). Nothing to do." << std::endl;
    }

    return result;
}

// DLL Entry Point
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
            if (MH_Initialize() != MH_OK)
            {
                return FALSE;
            }

            if (MH_CreateHook(&MessageBoxW, &HookedMessageBoxW, reinterpret_cast<LPVOID*>(&fpMessageBoxW)) != MH_OK)
            {
                return FALSE;
            }

            if (MH_EnableHook(&MessageBoxW) != MH_OK)
            {
                return FALSE;
            }
            break;

        case DLL_PROCESS_DETACH:
            MH_DisableHook(&MessageBoxW);
            MH_Uninitialize();
            break;
    }
    return TRUE;
}