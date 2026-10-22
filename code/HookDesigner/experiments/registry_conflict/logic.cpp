#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>   // NTSTATUS, UNICODE_STRING, OBJECT_ATTRIBUTES

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>


// Multiple instances of the same program use HKCU\Software\HookDesignerGuardrail\Shared. The first instance
// that opens it keeps it; every later instance is redirected to its own copy
// HKCU\Software\HookDesignerGuardrail\Shared_<pid>.
//
// Redirection happens at the ntdll layer (NtOpenKey / NtOpenKeyEx / NtCreateKey.
// Keys opened later relative to a redirected handle follow it automatically.

// @signatures-start
NTSTATUS NTAPI NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS NTAPI NtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions);
NTSTATUS NTAPI NtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition);
// @signatures-end

// Protected key
static const char kProtectedKey[] = "Software\\HookDesignerGuardrail\\Shared";

// Ownership flag shared by all instances
static const wchar_t kOwnershipMutex[] = L"Local\\HookDesignerGuardrail_Shared";

// Suffix of the copy's name: "_" + at most 10 digits of a 32-bit PID
static const size_t kSuffixChars = 1 + 10;


#include "../../suite/cpp/hd_paths.h"

static WCHAR g_RedirectedBuffer[sizeof(kProtectedKey) + kSuffixChars];
static UNICODE_STRING g_RedirectedName;

// Creates the copy of the protected key. Runs inside the pre-hook, where the recursion guard is held, so
// these Reg* calls reach the original ntdll functions and are not redirected.
static void CreateRedirectedCopy() {
    HKEY copy = nullptr;
    LSTATUS status = RegCreateKeyExW(HKEY_CURRENT_USER, g_RedirectedBuffer, 0, nullptr, REG_OPTION_NON_VOLATILE,
                                     KEY_ALL_ACCESS, nullptr, &copy, nullptr);
    if (status == ERROR_SUCCESS) {
        HKEY source = nullptr;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, kProtectedKey, 0, KEY_READ, &source) == ERROR_SUCCESS) {
            status = RegCopyTreeA(source, nullptr, copy);
            RegCloseKey(source);
        }
        RegCloseKey(copy);
    }
    if (status != ERROR_SUCCESS)
        OutputDebugStringA("[E3 guard-rail] creating the redirected copy failed\n");
}

// a named mutex, used only as a flag Creating it is atomic, so exactly one of two instances starting together sees it as new
static bool DecideOwnership() {
    SetLastError(ERROR_SUCCESS);
    HANDLE mutex = CreateMutexW(nullptr, FALSE, kOwnershipMutex);
    if (!mutex) {
        OutputDebugStringA("[E3 guard-rail] CreateMutexW failed: keeping the original key\n");
        return false;
    }
    if (GetLastError() != ERROR_ALREADY_EXISTS) return false;

    const int length = swprintf_s(g_RedirectedBuffer, L"%hs_%lu", kProtectedKey, GetCurrentProcessId());
    if (length <= 0) {
        OutputDebugStringA("[E3 guard-rail] building the copy's name failed: keeping the original key\n");
        return false;
    }
    g_RedirectedName.Buffer = g_RedirectedBuffer;
    g_RedirectedName.Length = g_RedirectedName.MaximumLength = (USHORT)(length * sizeof(WCHAR));
    CreateRedirectedCopy();
    return true;
}

// The decision is taken at this process's first open of the protected key and then reused:
//  - repeating it would redirect the owner itself (its own mutex makes CreateMutexW report ERROR_ALREADY_EXISTS);
//  - the copy must be created only once.
// A function-local static is initialized exactly once, and the initialization is thread-safe: a
// second thread opening the key at the same time waits for the first.
static bool IsRedirectedInstance() {
    static const bool redirected = DecideOwnership();
    return redirected;
}


// Redirection
static thread_local OBJECT_ATTRIBUTES t_RedirectedAttributes;

// Pre-hook of NtOpenKey / NtOpenKeyEx / NtCreateKey
// @RedirectSharedKey-start
static void RedirectSharedKey(POBJECT_ATTRIBUTES& ObjectAttributes) {
    if (!ObjectAttributes) return;
    if (_stricmp(CopyObjectName(ObjectAttributes).c_str(), kProtectedKey) != 0 || !IsRedirectedInstance()) return;

    t_RedirectedAttributes = *ObjectAttributes;            // same root, attributes and security descriptor
    t_RedirectedAttributes.ObjectName = &g_RedirectedName; 
    ObjectAttributes = &t_RedirectedAttributes;           
}
