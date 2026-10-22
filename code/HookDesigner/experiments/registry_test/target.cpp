#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

// The hook DLL's logger is asynchronous and is not flushed
// when the process exits: this pause lets it write the last events before exit
static const DWORD kLogDrainMs = 500;

// Helper to clean any keys from prior runs
void CleanupTestRoot() {
    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\HookDesignerTest", 0, KEY_ALL_ACCESS, &hRoot) == ERROR_SUCCESS) {
        // Delete subkeys if present
        RegDeleteKeyW(hRoot, L"Basic");
        RegDeleteKeyW(hRoot, L"EnumTest");
        RegCloseKey(hRoot);
        RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\HookDesignerTest");
    }
}

// SCENARIO 1: Standard Lifecycle
bool RunScenario1() {
    std::wcout << L"[SCENARIO 1 START] Standard Lifecycle" << std::endl;

    HKEY hKey = NULL;
    DWORD disposition = 0;

    // 1. Create Key
    LSTATUS status = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\HookDesignerTest\\Basic",
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        NULL,
        &hKey,
        &disposition
    );

    std::wcout << L"[1.1] RegCreateKeyExW: status=" << status 
               << L", disposition=" << (disposition == REG_CREATED_NEW_KEY ? L"CREATED_NEW" : L"OPENED_EXISTING") << std::endl;
    if (status != ERROR_SUCCESS) return false;

    // 2. Set DWORD Value
    DWORD dwordVal = 0xDEADBEEF;
    status = RegSetValueExW(hKey, L"TestDword", 0, REG_DWORD, (const BYTE*)&dwordVal, sizeof(dwordVal));
    std::wcout << L"[1.2] RegSetValueExW (REG_DWORD): status=" << status << std::endl;

    // 3. Set String Value
    const wchar_t* stringVal = L"HookDesigner Test String Value";
    DWORD stringBytes = (DWORD)((wcslen(stringVal) + 1) * sizeof(wchar_t));
    status = RegSetValueExW(hKey, L"TestString", 0, REG_SZ, (const BYTE*)stringVal, stringBytes);
    std::wcout << L"[1.3] RegSetValueExW (REG_SZ): status=" << status << std::endl;

    // 4. Set Binary Value
    BYTE binaryVal[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };
    status = RegSetValueExW(hKey, L"TestBinary", 0, REG_BINARY, binaryVal, sizeof(binaryVal));
    std::wcout << L"[1.4] RegSetValueExW (REG_BINARY): status=" << status << std::endl;

    // 5. Close Key Handle
    status = RegCloseKey(hKey);
    hKey = NULL;
    std::wcout << L"[1.5] RegCloseKey: status=" << status << std::endl;

    // 6. Re-open Key for Reading
    status = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\HookDesignerTest\\Basic", 0, KEY_READ, &hKey);
    std::wcout << L"[1.6] RegOpenKeyExW (KEY_READ): status=" << status << std::endl;
    if (status != ERROR_SUCCESS) return false;

    // 7. Query DWORD Value
    DWORD readDword = 0;
    DWORD readSize = sizeof(readDword);
    DWORD valType = 0;
    status = RegQueryValueExW(hKey, L"TestDword", NULL, &valType, (BYTE*)&readDword, &readSize);
    std::wcout << L"[1.7] RegQueryValueExW (TestDword): status=" << status << L", value=0x" << std::hex << readDword << std::dec << std::endl;

    // 8. Query String Value
    wchar_t readStr[128] = { 0 };
    readSize = sizeof(readStr);
    status = RegQueryValueExW(hKey, L"TestString", NULL, &valType, (BYTE*)readStr, &readSize);
    std::wcout << L"[1.8] RegQueryValueExW (TestString): status=" << status << L", value=\"" << readStr << L"\"" << std::endl;

    // 9. Query Binary Value
    BYTE readBin[16] = { 0 };
    readSize = sizeof(readBin);
    status = RegQueryValueExW(hKey, L"TestBinary", NULL, &valType, readBin, &readSize);
    std::wcout << L"[1.9] RegQueryValueExW (TestBinary): status=" << status << L", bytes=" << readSize << std::endl;

    // 10. Close Read Handle
    RegCloseKey(hKey);
    hKey = NULL;

    // 11. Re-open with KEY_SET_VALUE to delete values
    status = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\HookDesignerTest\\Basic", 0, KEY_SET_VALUE, &hKey);
    if (status == ERROR_SUCCESS) {
        status = RegDeleteValueW(hKey, L"TestDword");
        std::wcout << L"[1.10] RegDeleteValueW (TestDword): status=" << status << std::endl;

        status = RegDeleteValueW(hKey, L"TestBinary");
        std::wcout << L"[1.11] RegDeleteValueW (TestBinary): status=" << status << std::endl;

        status = RegDeleteValueW(hKey, L"TestString");
        std::wcout << L"[1.12] RegDeleteValueW (TestString): status=" << status << std::endl;

        RegCloseKey(hKey);
        hKey = NULL;
    }

    // 12. Delete Subkey
    HKEY hParent = NULL;
    status = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\HookDesignerTest", 0, KEY_ALL_ACCESS, &hParent);
    if (status == ERROR_SUCCESS) {
        status = RegDeleteKeyW(hParent, L"Basic");
        std::wcout << L"[1.13] RegDeleteKeyW (Basic): status=" << status << std::endl;
        RegCloseKey(hParent);
    }

    return true;
}

// SCENARIO 2: Errors
bool RunScenario2() {
    std::wcout << L"[SCENARIO 2 START] Error Paths & Boundary Handling" << std::endl;

    // 1. Open non-existent key
    HKEY hKey = NULL;
    LSTATUS status = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\HookDesignerTest\\NonExistent",
        0,
        KEY_READ,
        &hKey
    );
    std::wcout << L"[2.1] RegOpenKeyExW on non-existent key: status=" << status 
               << L" (expected=" << ERROR_FILE_NOT_FOUND << L")" << std::endl;

    // 2. Query non-existent value from existing key
    status = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\HookDesignerTest",
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        NULL,
        &hKey,
        NULL
    );
    if (status == ERROR_SUCCESS) {
        DWORD readVal = 0;
        DWORD readSize = sizeof(readVal);
        status = RegQueryValueExW(hKey, L"12345", NULL, NULL, (BYTE*)&readVal, &readSize);
        std::wcout << L"[2.2] RegQueryValueExW on non-existent value: status=" << status 
                   << L" (expected=" << ERROR_FILE_NOT_FOUND << L")" << std::endl;
        RegCloseKey(hKey);
        hKey = NULL;
    }

    // 3. Open HKLM with excessive write permissions (expected: ERROR_ACCESS_DENIED = 5)
    status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SECURITY",
        0,
        KEY_ALL_ACCESS,
        &hKey
    );
    std::wcout << L"[2.3] RegOpenKeyExW on HKLM with KEY_ALL_ACCESS: status=" << status 
               << L" (expected=" << ERROR_ACCESS_DENIED << L")" << std::endl;
    if (status == ERROR_SUCCESS) {
        RegCloseKey(hKey);
    }

    return true;
}


// SCENARIO 3: Enumeration & Key Metadata
bool RunScenario3() {
    std::wcout << L"[SCENARIO 3 START] Enumeration & Key Metadata" << std::endl;

    HKEY hEnumRoot = NULL;
    LSTATUS status = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\HookDesignerTest\\EnumTest",
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        NULL,
        &hEnumRoot,
        NULL
    );
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"Failed to create EnumTest parent key." << std::endl;
        return false;
    }

    // 1. Create 10 subkeys: SubKey_0 ... SubKey_9
    std::wcout << L"[3.1] Creating 10 subkeys under EnumTest..." << std::endl;
    for (int i = 0; i < 10; ++i) {
        std::wstring subName = L"SubKey_" + std::to_wstring(i);
        HKEY hSub = NULL;
        RegCreateKeyExW(hEnumRoot, subName.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hSub, NULL);
        if (hSub) RegCloseKey(hSub);
    }

    // 2. Create 10 values: Val_0 ... Val_9
    std::wcout << L"[3.2] Populating 10 values under EnumTest..." << std::endl;
    for (int i = 0; i < 10; ++i) {
        std::wstring valName = L"Val_" + std::to_wstring(i);
        DWORD valData = i * 100;
        RegSetValueExW(hEnumRoot, valName.c_str(), 0, REG_DWORD, (const BYTE*)&valData, sizeof(valData));
    }

    // 3. Query Key Metadata via RegQueryInfoKeyW
    DWORD numSubKeys = 0;
    DWORD maxSubKeyLen = 0;
    DWORD numValues = 0;
    DWORD maxValueNameLen = 0;
    DWORD maxValueLen = 0;
    FILETIME lastWriteTime = { 0 };

    status = RegQueryInfoKeyW(
        hEnumRoot,
        NULL, NULL, NULL,
        &numSubKeys,
        &maxSubKeyLen,
        NULL,
        &numValues,
        &maxValueNameLen,
        &maxValueLen,
        NULL,
        &lastWriteTime
    );

    std::wcout << L"[3.3] RegQueryInfoKeyW: status=" << status 
               << L", subKeysCount=" << numSubKeys 
               << L", valuesCount=" << numValues 
               << L", maxSubKeyLen=" << maxSubKeyLen 
               << L", maxValueNameLen=" << maxValueNameLen << std::endl;

    // 4. Enumerate subkeys via RegEnumKeyExW
    std::wcout << L"[3.4] Enumerating subkeys via RegEnumKeyExW:" << std::endl;
    for (DWORD i = 0; i < numSubKeys; ++i) {
        wchar_t nameBuf[256] = { 0 };
        DWORD nameLen = 256;
        status = RegEnumKeyExW(hEnumRoot, i, nameBuf, &nameLen, NULL, NULL, NULL, NULL);
        std::wcout << L"      Index " << i << L": Name=\"" << nameBuf << L"\", status=" << status << std::endl;
    }

    // 5. Enumerate values via RegEnumValueW
    std::wcout << L"[3.5] Enumerating values via RegEnumValueW:" << std::endl;
    for (DWORD i = 0; i < numValues; ++i) {
        wchar_t valNameBuf[256] = { 0 };
        DWORD valNameLen = 256;
        DWORD valType = 0;
        DWORD valData = 0;
        DWORD valDataLen = sizeof(valData);
        status = RegEnumValueW(hEnumRoot, i, valNameBuf, &valNameLen, NULL, &valType, (BYTE*)&valData, &valDataLen);
        std::wcout << L"      Index " << i << L": Name=\"" << valNameBuf << L"\", type=" << valType 
                   << L", val=" << valData << L", status=" << status << std::endl;
    }

    // 6. Cleanup subkeys and values
    std::wcout << L"[3.6] Cleaning up EnumTest subkeys and values..." << std::endl;
    for (int i = 0; i < 10; ++i) {
        std::wstring valName = L"Val_" + std::to_wstring(i);
        RegDeleteValueW(hEnumRoot, valName.c_str());

        std::wstring subName = L"SubKey_" + std::to_wstring(i);
        RegDeleteKeyW(hEnumRoot, subName.c_str());
    }

    RegCloseKey(hEnumRoot);

    // Delete EnumTest itself
    HKEY hParent = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\HookDesignerTest", 0, KEY_ALL_ACCESS, &hParent) == ERROR_SUCCESS) {
        RegDeleteKeyW(hParent, L"EnumTest");
        RegCloseKey(hParent);
    }

    return true;
}


int main() {
    std::wcout << L"HookDesigner vs ProcMon: Registry Test" << std::endl;
    std::wcout << L"PID: " << GetCurrentProcessId() << std::endl;

    CleanupTestRoot();

    RunScenario1();
    RunScenario2();
    RunScenario3();

    CleanupTestRoot();

    std::wcout << L"All Selected Scenarios Completed Successfully." << std::endl;

    Sleep(kLogDrainMs);
    return 0;
}
