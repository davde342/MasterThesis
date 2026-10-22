#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

// Not exported by the SDK user-mode headers (they live in the WDK's wdm.h).
typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation,
    KeyCachedInformation,
    KeyFlagsInformation,
    KeyVirtualizationInformation,
    KeyHandleTagsInformation,
    KeyTrustInformation,
    KeyLayerInformation,
    MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    KeyValueLayerInformation,
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

#include <cstdint>
#include <string>
#include <unordered_set>

// CopyObjectName / ObjectRoot (shared with other experiments). PUNICODE_STRING parameters are converted automatically
// by the transpiler; CopyObjectName is only needed because ObjectAttributes is a struct pointer.
#include "../../suite/cpp/hd_paths.h"

// @signatures-start
NTSTATUS NTAPI NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS NTAPI NtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions);
NTSTATUS NTAPI NtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition);
NTSTATUS NTAPI NtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
NTSTATUS NTAPI NtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize);
NTSTATUS NTAPI NtDeleteKey(HANDLE KeyHandle);
NTSTATUS NTAPI NtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName);
NTSTATUS NTAPI NtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
NTSTATUS NTAPI NtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
NTSTATUS NTAPI NtQueryKey(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
NTSTATUS NTAPI NtSetInformationKey(HANDLE KeyHandle, KEY_SET_INFORMATION_CLASS KeySetInformationClass, PVOID KeySetInformation, ULONG KeySetInformationLength);
NTSTATUS NTAPI NtClose(HANDLE Handle);
NTSTATUS NTAPI NtQuerySecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Length, PULONG LengthNeeded);
// @signatures-end


// NtClose closes every handle type and only receives a handle value, so key handles are remembered
// when NtOpenKey / NtOpenKeyEx / NtCreateKey succeed (post-hook) and NtClose is logged only for those.
//
// Race freedom: the handle is removed from the set in the NtClose PRE-hook, i.e. while the caller still
// owns it, so the value cannot be recycled by another thread's open before the erase. The pre-hook's
// verdict reaches the log condition through a per-thread flag (pre-hook -> True NtClose -> telemetry
// all run on the calling thread).


static SRWLOCK g_KeyHandlesLock = SRWLOCK_INIT;
static std::unordered_set<HANDLE>* g_KeyHandles = nullptr;

static thread_local bool t_ClosingKeyHandle = false;
static thread_local bool t_QueryingKeySecurity = false;

struct SrwSharedGuard {
    SRWLOCK* lock;
    SrwSharedGuard(SRWLOCK* l) : lock(l) { AcquireSRWLockShared(lock); }
    ~SrwSharedGuard() { ReleaseSRWLockShared(lock); }
};

struct SrwExclusiveGuard {
    SRWLOCK* lock;
    SrwExclusiveGuard(SRWLOCK* l) : lock(l) { AcquireSRWLockExclusive(lock); }
    ~SrwExclusiveGuard() { ReleaseSRWLockExclusive(lock); }
};

// Post-hook of NtOpenKey / NtOpenKeyEx / NtCreateKey
// @TrackOpenedKey-start
static void TrackOpenedKey(PHANDLE KeyHandle, NTSTATUS result) {
    if ((LONG)result < 0 || !KeyHandle) return;
    HANDLE handle = *KeyHandle; 
    if (!handle) return;
    SrwExclusiveGuard guard(&g_KeyHandlesLock);
    if (!g_KeyHandles) g_KeyHandles = new std::unordered_set<HANDLE>();
    g_KeyHandles->insert(handle);
}

// Pre-hook of NtClose. Hot path: every handle close in the process goes through here, so the common
// case (not a key) only takes the shared lock.
// @UntrackClosingKey-start
static void UntrackClosingKey(HANDLE Handle) {
    t_ClosingKeyHandle = false;
    {
        SrwSharedGuard guard(&g_KeyHandlesLock);
        if (!g_KeyHandles || g_KeyHandles->find(Handle) == g_KeyHandles->end()) return;
    }
    SrwExclusiveGuard guard(&g_KeyHandlesLock);
    t_ClosingKeyHandle = g_KeyHandles->erase(Handle) != 0;
}

// Log condition of the NtClose rule
static bool IsClosingKeyHandle() {
    return t_ClosingKeyHandle;
}

// Pre-hook of NtQuerySecurityObject: is the handle a tracked key? Checked BEFORE the call; the verdict reaches the log condition through a
// per-thread flag, assigned on every call. Shared lock only: the set is not modified.
// @CheckSecurityQueryHandle-start
static void CheckSecurityQueryHandle(HANDLE Handle) {
    SrwSharedGuard guard(&g_KeyHandlesLock);
    t_QueryingKeySecurity = g_KeyHandles && g_KeyHandles->find(Handle) != g_KeyHandles->end();
}

// Log condition of the NtQuerySecurityObject rule
static bool IsQueryingKeySecurity() {
    return t_QueryingKeySecurity;
}

