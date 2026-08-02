//////////////////////////////////////////////////////////////////////////////
//
//  Detours Test Program (trcuti.cpp of trcuti.dll)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//

#define _WIN32_WINNT        0x0501
#define WIN32
#define NT
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#define DBG_TRACE   0

#if _MSC_VER >= 1300
#include <winsock2.h>
#endif
#include <windows.h>
#include <mutex>
#include <vector>
#include <stdio.h>
#include "detours.h"
#include "..\syelog\syelog.h"
#include <thread>
#include <atomic>
#include <dbghelp.h>
#include <string>
#include <psapi.h>
#include <unordered_map>
#include <unordered_set>
#include <locale>
#include <codecvt>
#include <ApmsEnums.h>
#include <ErrorLog.h>
#include <ApmsQueue.h>
#include <chrono>
#include <Lib1090.h>
#include <PowerInterop.h>

#pragma comment(lib, "Rpcrt4.lib")


#define PULONG_PTR          PVOID
#define PLONG_PTR           PVOID
//#define ULONG_PTR           PVOID
#define ENUMRESNAMEPROCA    PVOID
#define ENUMRESNAMEPROCW    PVOID
#define ENUMRESLANGPROCA    PVOID
#define ENUMRESLANGPROCW    PVOID
#define ENUMRESTYPEPROCA    PVOID
#define ENUMRESTYPEPROCW    PVOID
#define STGOPTIONS          PVOID

//////////////////////////////////////////////////////////////////////////////
#pragma warning(disable:4127)   // Many of our asserts are constants.

#define ASSERT_ALWAYS(x)   \
    do {                                                        \
    if (!(x)) {                                                 \
            AssertMessage(const_cast<PCHAR>((PCHAR)#x), const_cast<PCHAR>((PCHAR)__FILE__), __LINE__);              \
            DebugBreak();                                       \
    }                                                           \
    } while (0)

#ifndef NDEBUG
#define ASSERT(x)           ASSERT_ALWAYS(x)
#else
#define ASSERT(x)
#endif

#define UNUSED(c)       (c) = (c)

//////////////////////////////////////////////////////////////////////////////
static HMODULE s_hInst = NULL;
static WCHAR s_wzDllPath[MAX_PATH];

VOID _PrintDump(SOCKET socket, PCHAR pszData, INT cbData);
VOID _PrintEnter(PCSTR psz, ...);
VOID _PrintExit(PCSTR psz, ...);
VOID _Print(PCSTR psz, ...);

VOID AssertMessage(CONST PCHAR pszMsg, CONST PCHAR pszFile, ULONG nLine);

std::string WStringToString(const std::wstring & wstr) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(wstr);
}



inline std::wstring AnsiToWide(LPCSTR str) {
    if (!str) return L"";
    int len = MultiByteToWideChar(CP_ACP, 0, str, -1, nullptr, 0);
    if (len <= 0) return L"";
    std::wstring out(static_cast<size_t>(len), L'\0'); // allocate full size
    MultiByteToWideChar(CP_ACP, 0, str, -1, &out[0], len);
    out.resize(len - 1); // remove the null terminator
    return out;
}



/////////////////////////////////////////////////////////////
// CUSTOM
//
std::atomic<bool> attached(false);
HINSTANCE phModule = nullptr;
int dwProcessId = 0;




struct TokenInfo {
    DWORD logonType = 0;
    DWORD logonProvider = 0;
    std::string user;   // from LogonUserA's input
    std::string domain; // from LogonUserA's input
    DWORD pid = 0;
    DWORD tid = 0;
    FILETIME created{};
};

class TokenLeakTracker {
public:
    static TokenLeakTracker& Instance() {
        static TokenLeakTracker inst;
        return inst;
    }

    void Register(HANDLE hToken,
        const char* user,
        const char* domain,
        DWORD logonType,
        DWORD logonProvider)
    {
        if (!hToken) return;
        std::lock_guard<std::mutex> lock(mutex_);
        TokenInfo info;
        info.logonType = logonType;
        info.logonProvider = logonProvider;
        info.user = user ? user : "";
        info.domain = domain ? domain : "";
        info.pid = GetCurrentProcessId();
        info.tid = GetCurrentThreadId();
        GetSystemTimeAsFileTime(&info.created);
        tokens_[hToken] = info;
    }

    void UnregisterIfClosed(HANDLE hToken, BOOL closeResult) {
        if (!hToken) return;
        std::lock_guard<std::mutex> lock(mutex_);
        if (closeResult) {
            auto it = tokens_.find(hToken);
            if (it != tokens_.end()) {
                tokens_.erase(it);
            }
        }
    }

    bool IsTracked(HANDLE hToken) {
        std::lock_guard<std::mutex> lock(mutex_);
        return tokens_.find(hToken) != tokens_.end();
    }

    std::vector<std::pair<HANDLE, TokenInfo>> Snapshot() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::pair<HANDLE, TokenInfo>> out;
        out.reserve(tokens_.size());
        for (auto& kv : tokens_) out.emplace_back(kv.first, kv.second);
        return out;
    }

private:
    TokenLeakTracker() = default;
    std::unordered_map<HANDLE, TokenInfo> tokens_;
    std::mutex mutex_;
};


/////////////////////////////////////////////////////////////
// DEFINE HERE THE HOOK FUNCTIONS
////////////////////////////////////////////////////////////////
//

typedef
LSTATUS
(APIENTRY*
    RegOpenKeyExA_t)(
        _In_ HKEY hKey,
        _In_opt_ LPCSTR lpSubKey,
        _In_opt_ DWORD ulOptions,
        _In_ REGSAM samDesired,
        _Out_ PHKEY phkResult
        );

RegOpenKeyExA_t Real_RegOpenKeyExA = RegOpenKeyExA;

LSTATUS
APIENTRY
Hooked_RegOpenKeyExA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
)
{
    std::ostringstream oss;
    oss << "[S+] RegOpenKeyExA | succeeded | SubKey=" << std::string(lpSubKey);
    _Print(oss.str().c_str());
    return Real_RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

typedef
LSTATUS
(APIENTRY*
    RegOpenKeyExW_t)(
        _In_ HKEY hKey,
        _In_opt_ LPCWSTR lpSubKey,
        _In_opt_ DWORD ulOptions,
        _In_ REGSAM samDesired,
        _Out_ PHKEY phkResult
        );

RegOpenKeyExW_t Real_RegOpenKeyExW = RegOpenKeyExW;

LSTATUS
APIENTRY
Hooked_RegOpenKeyExW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
)
{

    std::ostringstream oss;
    oss << "[S+] RegOpenKeyExW | succeeded | SubKey=" << WStringToString(std::wstring(lpSubKey));
    _Print(oss.str().c_str());
    return Real_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

typedef
LSTATUS
(APIENTRY*
    RegQueryValueExA_t)(
        _In_ HKEY hKey,
        _In_opt_ LPCSTR lpValueName,
        _Reserved_ LPDWORD lpReserved,
        _Out_opt_ LPDWORD lpType,
        _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
        _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
        );

RegQueryValueExA_t Real_RegQueryValueExA = RegQueryValueExA;

LSTATUS
APIENTRY
Hooked_RegQueryValueExA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
)
{
    std::ostringstream oss;
    oss << "[S+] RegQueryValueExA | succeeded | SubKey=" << std::string(lpValueName);
    _Print(oss.str().c_str());
    return Real_RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

typedef
LSTATUS
(APIENTRY*
    RegQueryValueExW_t)(
        _In_ HKEY hKey,
        _In_opt_ LPCWSTR lpValueName,
        _Reserved_ LPDWORD lpReserved,
        _Out_opt_ LPDWORD lpType,
        _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
        _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
        );

RegQueryValueExW_t Real_RegQueryValueExW = RegQueryValueExW;

LSTATUS
APIENTRY
Hooked_RegQueryValueExW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
)
{
    std::ostringstream oss;
    oss << "[S+] RegQueryValueExW | succeeded | SubKey=" << WStringToString(std::wstring(lpValueName));
    _Print(oss.str().c_str());
    return Real_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}













































static RETCOND(*Real_GETQ)(short*, short*, TIME1090, bool, HANDLE, int) = CQueue::GETQ;
static RETCOND(*Real_PUTQ)(short*, short*, TIME1090, void(*)(void*), HANDLE) = CQueue::PUTQ;
typedef int (WINAPI* SetInternalDipQueueEntries_t)(int iQueueIndex, int iNumPkt);
SetInternalDipQueueEntries_t Real_SetInternalDipQueueEntries = nullptr;

// INSERT IN THIS SECTION YOU CUSTOM HOOKS
std::atomic<size_t> logonUserCount;
std::atomic<size_t> CloseHandleCount;

typedef SECURITY_STATUS(SEC_ENTRY* AcquireCredentialsHandleA_t)(
        _In_opt_  LPSTR pszPrincipal,                 // Name of principal
        _In_      LPSTR pszPackage,                   // Name of package
        _In_      unsigned long fCredentialUse,       // Flags indicating use
        _In_opt_  void* pvLogonId,                   // Pointer to logon ID
        _In_opt_  void* pAuthData,                   // Package specific data
        _In_opt_  SEC_GET_KEY_FN pGetKeyFn,           // Pointer to GetKey() func
        _In_opt_  void* pvGetKeyArgument,            // Value to pass to GetKey()
        _Out_     PCredHandle phCredential,           // (out) Cred Handle
        _Out_opt_ PTimeStamp ptsExpiry                // (out) Lifetime (optional)
    );

typedef SECURITY_STATUS(SEC_ENTRY* AcquireCredentialsHandleW_t)(
#if ISSP_MODE == 0     // For Kernel mode
    _In_opt_  PSECURITY_STRING pPrincipal,
    _In_      PSECURITY_STRING pPackage,
#else
    _In_opt_  LPWSTR pszPrincipal,                // Name of principal
    _In_      LPWSTR pszPackage,                  // Name of package
#endif
    _In_      unsigned long fCredentialUse,       // Flags indicating use
    _In_opt_  void* pvLogonId,                   // Pointer to logon ID
    _In_opt_  void* pAuthData,                   // Package specific data
    _In_opt_  SEC_GET_KEY_FN pGetKeyFn,           // Pointer to GetKey() func
    _In_opt_  void* pvGetKeyArgument,            // Value to pass to GetKey()
    _Out_     PCredHandle phCredential,           // (out) Cred Handle
    _Out_opt_ PTimeStamp ptsExpiry                // (out) Lifetime (optional)
    );

typedef SECURITY_STATUS(SEC_ENTRY* FreeCredentialsHandle_t)(_In_ PCredHandle phCredential);


AcquireCredentialsHandleA_t TrueAcquireCredentialsHandleA = AcquireCredentialsHandleA;
AcquireCredentialsHandleW_t TrueAcquireCredentialsHandleW = AcquireCredentialsHandleW;
FreeCredentialsHandle_t TrueFreeCredentialsHandle = FreeCredentialsHandle;


SECURITY_STATUS SEC_ENTRY Hooked_AcquireCredentialsHandleA(
    _In_opt_  LPSTR pszPrincipal,
    _In_      LPSTR pszPackage,
    _In_      ULONG fCredentialUse,
    _In_opt_  PVOID pvLogonId,
    _In_opt_  PVOID pAuthData,
    _In_opt_  SEC_GET_KEY_FN pGetKeyFn,
    _In_opt_  PVOID pvGetKeyArgument,
    _Out_     PCredHandle phCredential,
    _Out_opt_ PTimeStamp ptsExpiry
) {
    // Call the original
    BOOL ok = TrueAcquireCredentialsHandleA(pszPrincipal, pszPackage, fCredentialUse,
        pvLogonId, pAuthData, pGetKeyFn,
        pvGetKeyArgument, phCredential, ptsExpiry);
    // If success and a token is returned, register it
    if (phCredential) {
        TokenLeakTracker::Instance().Register(phCredential,
            "",
            "",
            0,
            0);

        std::ostringstream oss;
        oss << "[S+] AcquireCredentialsHandleA | succeeded | token=" << phCredential;
        _Print(oss.str().c_str());
    }
    else {
        std::ostringstream oss;
        oss << "[S+] AcquireCredentialsHandleA UNTRACKED | succeeded | token=" << phCredential;
        _Print(oss.str().c_str());
    }
    return ok;
}

SECURITY_STATUS WINAPI Hooked_AcquireCredentialsHandleW(
#if ISSP_MODE == 0     // For Kernel mode
    _In_opt_  PSECURITY_STRING pPrincipal,
    _In_      PSECURITY_STRING pPackage,
#else
    _In_opt_  LPWSTR pszPrincipal,                // Name of principal
    _In_      LPWSTR pszPackage,                  // Name of package
#endif
    _In_      unsigned long fCredentialUse,       // Flags indicating use
    _In_opt_  void* pvLogonId,                   // Pointer to logon ID
    _In_opt_  void* pAuthData,                   // Package specific data
    _In_opt_  SEC_GET_KEY_FN pGetKeyFn,           // Pointer to GetKey() func
    _In_opt_  void* pvGetKeyArgument,            // Value to pass to GetKey()
    _Out_     PCredHandle phCredential,           // (out) Cred Handle
    _Out_opt_ PTimeStamp ptsExpiry                // (out) Lifetime (optional)
) {

    BOOL ok = FALSE;
#if ISSP_MODE == 0     // For Kernel mode
    ok = TrueAcquireCredentialsHandleW(// For Kernel mode
        pPrincipal,
        pPackage,
        fCredentialUse,
        pvLogonId, pAuthData, pGetKeyFn,
        pvGetKeyArgument, phCredential, ptsExpiry);
#else
    ok = TrueAcquireCredentialsHandleW(
        pszPrincipal,
        pszPackage,
        fCredentialUse,
        pvLogonId, pAuthData, pGetKeyFn,
        pvGetKeyArgument, phCredential, ptsExpiry);
#endif
        
    // If success and a token is returned, register it
    if (phCredential) {
        TokenLeakTracker::Instance().Register(phCredential,
            "",
            "",
            0,
            0);

        std::ostringstream oss;
        oss << "[S+] AcquireCredentialsHandleW | succeeded | token=" << phCredential;
        _Print(oss.str().c_str());
    }
    else {
        std::ostringstream oss;
        oss << "[S+] AcquireCredentialsHandleW UNTRACKED | succeeded | token=" << phCredential;
        _Print(oss.str().c_str());
    }
    return ok;
}

SECURITY_STATUS SEC_ENTRY Hooked_FreeCredentialsHandle(_In_ PCredHandle phCredential) {

    bool tracked = TokenLeakTracker::Instance().IsTracked(phCredential);
    BOOL ok = TrueFreeCredentialsHandle(phCredential);

    if (tracked) 
    {
        TokenLeakTracker::Instance().UnregisterIfClosed(phCredential, ok);

        std::ostringstream oss;
        oss << "[S+] FreeCredentialsHandle | Status: "
            << (ok ? "succeeded" : "FAILED")
            << "| for token=" << phCredential
            << (ok ? " (untracked now)" : " (still tracked)");
        _Print(oss.str().c_str());
    }
    else {
        std::ostringstream oss;
        oss << "[S+] FreeCredentialsHandle UNTRACKED | Status: "
            << (ok ? "succeeded" : "FAILED")
            << "| for token=" << phCredential
            << (ok ? " (untracked now)" : " (still tracked)");
        _Print(oss.str().c_str());
    }
    return ok;
}


typedef BOOL (WINAPI* CloseHandle_t)(_In_ _Post_ptr_invalid_ HANDLE hObject);
CloseHandle_t TheReal_CloseHandle = CloseHandle;

BOOL WINAPI Hooked_CloseHandle(_In_ _Post_ptr_invalid_ HANDLE hObject) 
{
    bool tracked = TokenLeakTracker::Instance().IsTracked(hObject);
    BOOL ok = TheReal_CloseHandle(hObject);

    if (tracked) {
        TokenLeakTracker::Instance().UnregisterIfClosed(hObject, ok);

        std::ostringstream oss;
        oss << "[S+] CloseHandle | Status: "
            << (ok ? "succeeded" : "FAILED")
            << "| for token=" << hObject
            << (ok ? " (untracked now)" : " (still tracked)");
        _Print(oss.str().c_str());
    }
    return ok;
}

typedef BOOL (WINAPI* LogonUserA_t)(
    _In_        LPCSTR lpszUsername,
    _In_opt_    LPCSTR lpszDomain,
    _In_opt_    LPCSTR lpszPassword,
    _In_        DWORD dwLogonType,
    _In_        DWORD dwLogonProvider,
    _Outptr_ PHANDLE phToken
);
LogonUserA_t Real_LogonUserA = LogonUserA;

BOOL WINAPI Hooked_LogonUserA(
    _In_        LPCSTR lpszUsername,
    _In_opt_    LPCSTR lpszDomain,
    _In_opt_    LPCSTR lpszPassword,
    _In_        DWORD dwLogonType,
    _In_        DWORD dwLogonProvider,
    _Outptr_ PHANDLE phToken
)
{

    // Call the original
    BOOL ok = Real_LogonUserA(lpszUsername, lpszDomain, lpszPassword,
        dwLogonType, dwLogonProvider, phToken);
    // If success and a token is returned, register it
    if (ok && phToken && *phToken) {
        TokenLeakTracker::Instance().Register(*phToken,
            lpszUsername,
            lpszDomain,
            dwLogonType,
            dwLogonProvider);

        std::ostringstream oss;
        oss << "[S+] LogonUserA | succeeded | token=" << *phToken
            << " user=\"" << (lpszUsername ? lpszUsername : "") << "\""
            << " domain=\"" << (lpszDomain ? lpszDomain : "") << "\""
            << " type=" << dwLogonType
            << " provider=" << dwLogonProvider;
        _Print(oss.str().c_str());
    }
    return ok;
}

typedef BOOL
(WINAPI*
LogonUserW_t)(
    _In_        LPCWSTR lpszUsername,
    _In_opt_    LPCWSTR lpszDomain,
    _In_opt_    LPCWSTR lpszPassword,
    _In_        DWORD dwLogonType,
    _In_        DWORD dwLogonProvider,
    _Outptr_ PHANDLE phToken
);

LogonUserW_t Real_LogonUserW = LogonUserW;

BOOL WINAPI Hooked_LogonUserW(
    _In_        LPCWSTR lpszUsername,
    _In_opt_    LPCWSTR lpszDomain,
    _In_opt_    LPCWSTR lpszPassword,
    _In_        DWORD dwLogonType,
    _In_        DWORD dwLogonProvider,
    _Outptr_ PHANDLE phToken
)
{
    std::wstring lpszUsernameStr(lpszUsername);
    std::wstring lpszDomainStr(lpszDomain);
    // Call the original
    BOOL ok = Real_LogonUserW(lpszUsername, lpszDomain, lpszPassword,
        dwLogonType, dwLogonProvider, phToken);
    // If success and a token is returned, register it
    if (ok && phToken && *phToken) {
        TokenLeakTracker::Instance().Register(*phToken,
            WStringToString(lpszUsernameStr).c_str(),
            WStringToString(lpszDomainStr).c_str(),
            dwLogonType,
            dwLogonProvider);

        std::ostringstream oss;
        oss << "[S+] LogonUserW | succeeded | token=" << *phToken
            << " user=\"" << (lpszUsername ? WStringToString(lpszUsernameStr).c_str() : "") << "\""
            << " domain=\"" << (lpszDomain ? WStringToString(lpszDomainStr).c_str() : "") << "\""
            << " type=" << dwLogonType
            << " provider=" << dwLogonProvider;
        _Print(oss.str().c_str());
    }
    return ok;
}

typedef bool (__cdecl* Real_PwTag_Write_t)(float value, uint64_t qual, TAGWRITE_OPTIONS dwOptions, PwTime * pTime);
Real_PwTag_Write_t Real_PwTag_Write = nullptr;

bool __cdecl  Hooked_PwTag_Write(PwTag * pThis, float value, uint64_t qual, TAGWRITE_OPTIONS dwOptions, PwTime * pTime) {

    //auto wideTagName = pThis->GetName().c_str();
    //char tagName[256];
    //int result = WideCharToMultiByte(CP_UTF8, 0, wideTagName, -1, tagName, sizeof(tagName), nullptr, nullptr);
    //std::string message = "[TAG WRITE] Tag: " + std::string(tagName) + ", Value: " + std::to_string(value) + ", Quality: " + std::to_string(qual);
    //_Print(message.c_str());
    return Real_PwTag_Write(value, qual, dwOptions, pTime);
}

//****************************************

// Detour function
struct QueueEntry {
    std::atomic<short*> ptr;
    std::atomic<size_t> putCount;
    std::atomic<size_t> getCount;
};

constexpr size_t MAX_ENTRIES = 1024;
QueueEntry table[MAX_ENTRIES];
std::atomic<size_t> internalQueue;

// Initialize table
void InitTable() {
    for (size_t i = 0; i < MAX_ENTRIES; ++i) {
        table[i].ptr.store(nullptr, std::memory_order_relaxed);
        table[i].putCount.store(0, std::memory_order_relaxed);
        table[i].getCount.store(0, std::memory_order_relaxed);
    }
}

// Increment counters for a queue
void IncrementCounter(short* pQueue, bool isPut) {
    for (size_t i = 0; i < MAX_ENTRIES; ++i) {
        short* current = table[i].ptr.load(std::memory_order_relaxed);

        if (current == pQueue) {
            if (isPut) table[i].putCount.fetch_add(1, std::memory_order_relaxed);
            else table[i].getCount.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        if (current == nullptr) {
            if (table[i].ptr.compare_exchange_strong(current, pQueue, std::memory_order_relaxed)) {
                if (isPut) table[i].putCount.store(1, std::memory_order_relaxed);
                else table[i].getCount.store(1, std::memory_order_relaxed);
                return;
            }
        }
    }
}

// Reset counters for a specific queue
bool ResetCounters(short* pQueue = nullptr) {
    for (size_t i = 0; i < MAX_ENTRIES; ++i) {
        short* current = table[i].ptr.load(std::memory_order_relaxed);
        if (current == pQueue) {
            table[i].putCount.store(0, std::memory_order_relaxed);
            table[i].getCount.store(0, std::memory_order_relaxed);
            return true;
        }
    }
    return false;
}

std::string PointerInfo(short* ptr) {
    std::ostringstream oss;
    if (ptr) {
        auto hdr = reinterpret_cast<LP_STD_QUEUE_HDR>(ptr);
        std::wstring qwname(hdr->name);
        std::string qname;
        qname.assign(qwname.begin(), qwname.end());
        oss << "[Queue Addr: " << ptr << " | Queue Name:" << qname << "]";
    }
    else {
        oss << "null";
    }
    return oss.str();
}

// Print all counters
void PrintStats() {
	auto internalPut = internalQueue.exchange(0, std::memory_order_relaxed);
    if(internalPut != 0) {
        std::string msg2 = "[INJECTED_STATS_QUEUE] [Queue Addr: <INTERNAL> | Queue Name: INTERNAL_DIP1] | #GET: 0 samples | #PUT " + std::to_string(internalPut) + " samples.";
        _Print(msg2.c_str());
	}
    for (size_t i = 0; i < MAX_ENTRIES; ++i) {
        short* current = table[i].ptr.load(std::memory_order_relaxed);
        if (current != nullptr) {
            size_t put = table[i].putCount.exchange(0, std::memory_order_relaxed);
            size_t get = table[i].getCount.exchange(0, std::memory_order_relaxed);
			if (put == 0 && get == 0) continue; // Skip if no activity
            std::string msg2 = "[INJECTED_STATS_QUEUE] " + PointerInfo(current) + " | #GET: " + std::to_string(get) + " samples | #PUT " + std::to_string(put) + " samples.";
			_Print(msg2.c_str());
        }
    }
}

// Hooks
int WINAPI My_SetInternalDipQueueEntries(int iQueueIndex, int iNumPkt)
{
	internalQueue.fetch_add(1, std::memory_order_relaxed);
    return Real_SetInternalDipQueueEntries(iQueueIndex, iNumPkt);
}

RETCOND Hooked_PUTQ(short* pQueue, short* pBlk, TIME1090 tInputTime,
    void(*ProcessEntry)(void*), HANDLE hNotifyEvent) {
    IncrementCounter(pQueue, true);
    return Real_PUTQ(pQueue, pBlk, tInputTime, ProcessEntry, hNotifyEvent);
}

RETCOND Hooked_GETQ(short* pQueue, short* pBlk, TIME1090 tInputTime,
    bool bWaitForNotifyEvent, HANDLE hNotifyEvent, int iMsTimeout) {
    RETCOND result = Real_GETQ(pQueue, pBlk, tInputTime, bWaitForNotifyEvent, hNotifyEvent, iMsTimeout);
    IncrementCounter(pQueue, false);
    return result;
}

class CDetour /* add ": public CMember" to enable access to member variables... */
{
public:
    RETCOND Mine_TargetPut(LPLOG_QENTRY pPack);
    static RETCOND(CDetour::* Real_TargetPut)(LPLOG_QENTRY pPack);
};

RETCOND CDetour::Mine_TargetPut(LPLOG_QENTRY pPack)
{
    std::string message = "[S+] " + WStringToString(pPack->logData);
    _Print(message.c_str());
    return (this->*Real_TargetPut)(pPack);
}

VOID _PrintDump(SOCKET socket, PCHAR pszData, INT cbData)
{
    if (pszData && cbData > 0) {
        CHAR szBuffer[256];
        PCHAR pszBuffer = szBuffer;
        INT cbBuffer = 0;
        INT nLines = 0;

        while (cbData > 0) {
            if (nLines > 20) {
                *pszBuffer++ = '.';
                *pszBuffer++ = '.';
                *pszBuffer++ = '.';
                cbBuffer += 3;
                break;
            }

            if (*pszData == '\t') {
                *pszBuffer++ = '\\';
                *pszBuffer++ = 't';
                cbBuffer += 2;
                pszData++;
                cbData--;
                continue;
            }
            if (*pszData == '\r') {
                *pszBuffer++ = '\\';
                *pszBuffer++ = 'r';
                cbBuffer += 2;
                pszData++;
                cbData--;
                continue;
            }
            else if (*pszData == '\n') {
                *pszBuffer++ = '\\';
                *pszBuffer++ = 'n';
                cbBuffer += 2;
                *pszBuffer++ = '\0';
                _Print("SOCKET [%p]:   %hs\n", socket, szBuffer);
                nLines++;
                pszBuffer = szBuffer;
                cbBuffer = 0;
                pszData++;
                cbData--;
                continue;
            }
            else if (cbBuffer >= 80) {
                *pszBuffer++ = '\0';
                _Print("SOCKET [%p]:   %hs\n", socket, szBuffer);
                nLines++;
                pszBuffer = szBuffer;
                cbBuffer = 0;
            }

            if (*pszData < ' ' || *pszData >= 127) {
                *pszBuffer++ = '\\';
                *pszBuffer++ = 'x';
                *pszBuffer++ = "0123456789ABCDEF"[(*pszData & 0xf0) >> 4];
                *pszBuffer++ = "0123456789ABCDEF"[(*pszData & 0x0f)];
                cbBuffer += 4;
            }
            else {
                *pszBuffer++ = *pszData;
            }
            cbBuffer++;
            pszData++;
            cbData--;
        }

        if (cbBuffer > 0) {
            *pszBuffer++ = '\0';
            _Print("SOCKET [%p]:   %hs\n", socket, szBuffer);
        }
    }
}

/////////////////////////////////////////////////////////////
// AttachDetours
//
PCHAR DetRealName(PCHAR psz)
{
    PCHAR pszBeg = psz;
    // Move to end of name.
    while (*psz) {
        psz++;
    }
    // Move back through A-Za-z0-9 names.
    while (psz > pszBeg &&
           ((psz[-1] >= 'A' && psz[-1] <= 'Z') ||
            (psz[-1] >= 'a' && psz[-1] <= 'z') ||
            (psz[-1] >= '0' && psz[-1] <= '9'))) {
        psz--;
    }
    return psz;
}

VOID DetAttach(PVOID *ppbReal, PVOID pbMine, PCHAR psz)
{
    LONG l = DetourAttach(ppbReal, pbMine);
    if (l != 0) {
        Syelog(SYELOG_SEVERITY_NOTICE,
               "Attach failed: `%s': error %d\n", DetRealName(psz), l);
    }
}

VOID DetDetach(PVOID *ppbReal, PVOID pbMine, PCHAR psz)
{
    LONG l = DetourDetach(ppbReal, pbMine);
    if (l != 0) {
        Syelog(SYELOG_SEVERITY_NOTICE,
               "Detach failed: `%s': error %d\n", DetRealName(psz), l);
    }
}

#define ATTACH(x)       DetAttach(&(PVOID&)Real_##x,Mine_##x,(PCHAR)#x)
#define DETACH(x)       DetDetach(&(PVOID&)Real_##x,Mine_##x,(PCHAR)#x)


// Original function pointers
decltype(SetUnhandledExceptionFilter)* TrueSetUnhandledExceptionFilter = SetUnhandledExceptionFilter;
decltype(AddVectoredExceptionHandler)* TrueAddVectoredExceptionHandler = AddVectoredExceptionHandler;
decltype(RaiseException)* TrueRaiseException = RaiseException;
RETCOND(CDetour::* CDetour::Real_TargetPut)(LPLOG_QENTRY) = (RETCOND(CDetour::*)(LPLOG_QENTRY)) & CLogQueue::Put;
RETCOND(CDetour::* pfMinePut)(LPLOG_QENTRY) = &CDetour::Mine_TargetPut;



BOOL InitSymbols() {
    return SymInitialize(GetCurrentProcess(), NULL, TRUE);
}

void LogStackTrace(std::string exceptionGuid, CONTEXT* context) {
    HANDLE process = GetCurrentProcess();
    HANDLE thread = GetCurrentThread();

    STACKFRAME64 stackFrame = {};
    DWORD machineType = IMAGE_FILE_MACHINE_AMD64;

    stackFrame.AddrPC.Offset = context->Rip;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = context->Rbp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = context->Rsp;
    stackFrame.AddrStack.Mode = AddrModeFlat;

    for (int frame = 0; frame < 20; ++frame) {
        if (!StackWalk64(machineType, process, thread, &stackFrame, context, NULL,
            SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
            break;
        }

        char symbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
        SYMBOL_INFO* symbol = (SYMBOL_INFO*)symbolBuffer;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = MAX_SYM_NAME;

        DWORD64 address = stackFrame.AddrPC.Offset;
        if (SymFromAddr(process, address, 0, symbol)) {
			std::string msg = "[Stack] [#" +exceptionGuid + "#] %s at " + std::to_string(symbol->Address);
            _Print(msg.c_str(), symbol->Name);
        }
        else {
            std::string msg = "Unknown [#" + exceptionGuid + "#] symbol at " + std::to_string(address);
            _Print(msg.c_str());
        }
    }
}

const char* GetExceptionType(DWORD code) {
    switch (code) {
    case 0xC0000005: return "Access Violation";
    case 0xC0000094: return "Integer Divide by Zero";
    case 0xC000008C: return "Array Bounds Exceeded";
    case 0xC000001D: return "Illegal Instruction";
    case 0x80000003: return "Breakpoint";
    case 0xE06D7363: return "C++ Exception";
    case 0xC00000FD: return "Stack Overflow";
    case 0xC0000008: return "Invalid Handle";
    case 0xC0000006: return "In-page I/O Error";
    case 0xC0000135: return "DLL Not Found";
    case 0xC0000139: return "Entry Point Not Found";
    case 0xC0000142: return "DLL Initialization Failed";
    case 0xC0000095: return "Floating Point Underflow";
    case 0xC0000096: return "Privileged Instruction";
    case 0xC0000097: return "Floating Point Overflow";
    case 0xC00000F0: return "Floating Point Exception";
    default: return "Unknown Exception";
    }
}

#pragma comment(lib, "dbghelp.lib")

void LogExceptionOrigin(std::string exceptionGuid, PVOID exceptionAddress) {
    HANDLE process = GetCurrentProcess();

    // Initialize symbol info structure
    char symbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
    SYMBOL_INFO* symbol = (SYMBOL_INFO*)symbolBuffer;
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = MAX_SYM_NAME;

    DWORD64 displacement = 0;

    if (SymFromAddr(process, (DWORD64)exceptionAddress, &displacement, symbol)) {
        std::string msg = "[Origin] Exception [#"+ exceptionGuid + "#] thrown at : % s + " + std::to_string(displacement) + " (" + std::to_string(symbol->Address) + ")";
        _Print(msg.c_str(), symbol->Name);
    }
    else {
        std::string msg = "[Origin] Exception [#" + exceptionGuid + "#] thrown at unknown symbol (0x%p)";
        _Print(msg.c_str(), exceptionAddress);
    }
}

void WINAPI MyRaiseException(
    DWORD dwExceptionCode,
    DWORD dwExceptionFlags,
    DWORD nNumberOfArguments,
    const ULONG_PTR* lpArguments
) {
	auto exType = GetExceptionType(dwExceptionCode);
    
    UUID uuid;
    UuidCreate(&uuid);
    RPC_CSTR uuidcstr;
    UuidToStringA(&uuid, &uuidcstr);
    std::string exceptionGuid(reinterpret_cast<char *>(uuidcstr));
	std::string message = "[RaiseException] Exception [#" + exceptionGuid +"#] raised Type: %s Code: 0x%08X, Flags: 0x%08X, Args: %d";
    _Print(message.c_str(), exType, dwExceptionCode, dwExceptionFlags, nNumberOfArguments);

    CONTEXT context = {};
    RtlCaptureContext(&context);
    LogStackTrace(exceptionGuid, &context);

    // Call original
    TrueRaiseException(dwExceptionCode, dwExceptionFlags, nNumberOfArguments, lpArguments);
}


LONG WINAPI MyUnhandledExceptionFilter(EXCEPTION_POINTERS* ExceptionInfo) {
    // Log exception details
    auto exType = GetExceptionType(ExceptionInfo->ExceptionRecord->ExceptionCode);

    UUID uuid;
    UuidCreate(&uuid);
    RPC_CSTR uuidcstr;
    UuidToStringA(&uuid, &uuidcstr);
    std::string exceptionGuid(reinterpret_cast<char*>(uuidcstr));
	std::string message = "[UEF] Unhandled Exception [#" + exceptionGuid + "#] Type: %s Code: 0x%08X at Address: %p";
    
    _Print(message.c_str(),
		exType,
        ExceptionInfo->ExceptionRecord->ExceptionCode,
        ExceptionInfo->ExceptionRecord->ExceptionAddress);
	LogExceptionOrigin(exceptionGuid, ExceptionInfo->ExceptionRecord->ExceptionAddress);
    LogStackTrace(exceptionGuid, ExceptionInfo->ContextRecord);
    return EXCEPTION_EXECUTE_HANDLER;
}

PVOID WINAPI MyAddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler) {
    // Log that a handler was added
    UUID uuid;
    UuidCreate(&uuid);
    RPC_CSTR uuidcstr;
    UuidToStringA(&uuid, &uuidcstr);
    std::string exceptionGuid(reinterpret_cast<char*>(uuidcstr));
	std::string message = "[AddVEH] Adding Vectored Exception Handler [#" + exceptionGuid + "#]";
    _Print(message.c_str());
    CONTEXT context = {};
    RtlCaptureContext(&context);
    LogStackTrace(exceptionGuid, &context);
    return TrueAddVectoredExceptionHandler(First, Handler);
}

LONG WINAPI MyVectoredHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    UUID uuid;
    UuidCreate(&uuid);
    RPC_CSTR uuidcstr;
    UuidToStringA(&uuid, &uuidcstr);
    std::string exceptionGuid(reinterpret_cast<char*>(uuidcstr));
	std::string message = "[VEH] Exception [#" + exceptionGuid + "#] Type: %s Code: 0x%08X at Address: %p.";

    auto exType = GetExceptionType(ExceptionInfo->ExceptionRecord->ExceptionCode);
    _Print(message.c_str(),
		exType,
        ExceptionInfo->ExceptionRecord->ExceptionCode,
        ExceptionInfo->ExceptionRecord->ExceptionAddress);
    LogExceptionOrigin(exceptionGuid, ExceptionInfo->ExceptionRecord->ExceptionAddress);
    CONTEXT context = {};
    RtlCaptureContext(&context);
    LogStackTrace(exceptionGuid, &context);
    return EXCEPTION_CONTINUE_SEARCH;
}

// Original function pointers
static void (WINAPI* OriginalEnterCriticalSection)(LPCRITICAL_SECTION) = EnterCriticalSection;
static void (WINAPI* OriginalLeaveCriticalSection)(LPCRITICAL_SECTION) = LeaveCriticalSection;
static DWORD(WINAPI* OriginalWaitForSingleObject)(HANDLE, DWORD) = WaitForSingleObject;
static BOOL(WINAPI* OriginalReleaseMutex)(HANDLE) = ReleaseMutex;
static BOOL(WINAPI* OriginalReleaseSemaphore)(HANDLE, LONG, LPLONG) = ReleaseSemaphore;

// Counters
std::atomic<uint64_t> enterCount{ 0 };
std::atomic<uint64_t> leaveCount{ 0 };
std::atomic<uint64_t> waitCount{ 0 };
std::atomic<uint64_t> releaseMutexCount{ 0 };
std::atomic<uint64_t> releaseSemaphoreCount{ 0 };
std::atomic<bool> reportingEnabled{ false };

// Timing
auto lastReset = std::chrono::steady_clock::now();

// Hooks
void WINAPI MyEnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
    enterCount++;
    OriginalEnterCriticalSection(lpCriticalSection);
}

void WINAPI MyLeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
    leaveCount++;
    OriginalLeaveCriticalSection(lpCriticalSection);
}

DWORD WINAPI MyWaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    DWORD result = OriginalWaitForSingleObject(hHandle, dwMilliseconds);
    if (result == WAIT_OBJECT_0) {
        waitCount++;
    }
    return result;
}

BOOL WINAPI MyReleaseMutex(HANDLE hMutex) {
    releaseMutexCount++;
    return OriginalReleaseMutex(hMutex);
}

BOOL WINAPI MyReleaseSemaphore(HANDLE hSemaphore, LONG lReleaseCount, LPLONG lpPreviousCount) {
    releaseSemaphoreCount++;
    return OriginalReleaseSemaphore(hSemaphore, lReleaseCount, lpPreviousCount);
}

void ReportInsights() 
{
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - lastReset).count();

    uint64_t e = enterCount.exchange(0);
    uint64_t l = leaveCount.exchange(0);
    uint64_t w = waitCount.exchange(0);
    uint64_t rm = releaseMutexCount.exchange(0);
    uint64_t rs = releaseSemaphoreCount.exchange(0);
	auto allReleases = rm + rs;
    auto activeMS = waitCount > allReleases ? waitCount - allReleases : 0;

	auto activeCs = e > l ? e - l : 0;

    std::string msg = "[INJECTED_STATS_LOCKS] Stats after " + std::to_string(elapsed) + " seconds"
        " | CS Enter/sec: " + std::to_string(static_cast<int>(std::round(e / elapsed))) +
        " | CS Leave/sec: " + std::to_string(static_cast<int>(std::round(l / elapsed))) +
        " | Mutex/Sem Wait/sec: " + std::to_string(static_cast<int>(std::round(w / elapsed))) +
        " | Mutex/Sem Release/sec: " + std::to_string(static_cast<int>(std::round(allReleases / elapsed))) +
        " | Ongoing CS: " + std::to_string(activeCs) +
        " | Ongoing Mutex/Semaphore: " + std::to_string(activeMS);

    _Print(msg.c_str());
    PrintStats();

    std::string msgTokens = "[INJECTED_STATS_TOKENS] NOT YET COLLECTED: " + std::to_string(TokenLeakTracker::Instance().Snapshot().size());
    _Print(msgTokens.c_str());

    lastReset = now;
}

// Print stats on demand
extern "C" __declspec(dllexport) void START_REPORT_INSIGHTS_Command() {
   if(reportingEnabled.exchange(true) == false) {
       std::thread([]() {
           while (reportingEnabled.load()) {
               ReportInsights();

               std::this_thread::sleep_for(std::chrono::seconds(1));
           }
       }).detach();
   }
}

// Print stats on demand
extern "C" __declspec(dllexport) void STOP_REPORT_INSIGHTS_Command() {
   if(reportingEnabled.exchange(false) == true) {
       // Final report
       ReportInsights();
   }
}

LONG HookFunctions() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    AddVectoredExceptionHandler(1, AddVectoredExceptionHandler);
    Syelog(SYELOG_SEVERITY_INFORMATION,"[Hooked] AddVectoredExceptionHandler");
    DetourAttach(&(PVOID&)TrueRaiseException, MyRaiseException);
    Syelog(SYELOG_SEVERITY_INFORMATION, "[Hooked] RaiseException");
    DetourAttach(&(PVOID&)TrueSetUnhandledExceptionFilter, MyUnhandledExceptionFilter);
    Syelog(SYELOG_SEVERITY_INFORMATION, "[Hooked] UnhandledExceptionFilter");
    DetourAttach(&(PVOID&)TrueAddVectoredExceptionHandler, MyAddVectoredExceptionHandler);
    Syelog(SYELOG_SEVERITY_INFORMATION, "[Hooked] UnhandledExceptionFilter");
    DetourAttach(&(PVOID&)OriginalEnterCriticalSection, MyEnterCriticalSection);
    Syelog(SYELOG_SEVERITY_INFORMATION, "[Hooked] EnterCriticalSection");
    DetourAttach(&(PVOID&)OriginalLeaveCriticalSection, MyLeaveCriticalSection);
    Syelog(SYELOG_SEVERITY_INFORMATION, "[Hooked] LeaveCriticalSection");
    DetourAttach(&(PVOID&)OriginalWaitForSingleObject, MyWaitForSingleObject);
    Syelog(SYELOG_SEVERITY_INFORMATION, "[Hooked] WaitForSingleObject");
    DetourAttach(&(PVOID&)OriginalReleaseMutex, MyReleaseMutex);
    Syelog(SYELOG_SEVERITY_INFORMATION, "[Hooked] ReleaseMutex");
    DetourAttach(&(PVOID&)OriginalReleaseSemaphore, MyReleaseSemaphore);
    Syelog(SYELOG_SEVERITY_INFORMATION, "[Hooked] ReleaseSemaphore");
    DetourAttach(&(PVOID&)CDetour::Real_TargetPut, *(PBYTE*)&pfMinePut);
    Syelog(SYELOG_SEVERITY_INFORMATION, "[S+ Hooked] CLogQueue::Put");
    DetourAttach(&(PVOID&)Real_GETQ, Hooked_GETQ);
    Syelog(SYELOG_SEVERITY_INFORMATION, "[S+ Hooked] CQueue::GETQ");
    DetourAttach(&(PVOID&)Real_PUTQ, Hooked_PUTQ);
    Syelog(SYELOG_SEVERITY_INFORMATION, "[S+ Hooked] CQueue::PUTQ");
    if (Real_SetInternalDipQueueEntries != nullptr) 
    {
        DetourAttach(&(PVOID&)Real_SetInternalDipQueueEntries, My_SetInternalDipQueueEntries);
        Syelog(SYELOG_SEVERITY_INFORMATION, "[S+ Hooked] shr1090::SetInternalDipQueueEntries");
    }

    // ATTACH HERE YOUR CUSTOM HOOK


    DetourAttach(&(PVOID&)Real_RegOpenKeyExA, Hooked_RegOpenKeyExA);
    Syelog(SYELOG_SEVERITY_INFORMATION, "[S+ Hooked] RegOpenKeyExA");
    DetourAttach(&(PVOID&)Real_RegOpenKeyExW, Hooked_RegOpenKeyExW);
    Syelog(SYELOG_SEVERITY_INFORMATION, "[S+ Hooked] RegOpenKeyExW");
    DetourAttach(&(PVOID&)Real_RegQueryValueExA, Hooked_RegQueryValueExA);
    Syelog(SYELOG_SEVERITY_INFORMATION, "[S+ Hooked] RegQueryValueExA");
    DetourAttach(&(PVOID&)Real_RegQueryValueExW, Hooked_RegQueryValueExW);
    Syelog(SYELOG_SEVERITY_INFORMATION, "[S+ Hooked] RegQueryValueExW");

    ///////////////////////////////


    return DetourTransactionCommit();
}

LONG DeHookFunctions() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach(&(PVOID&)TrueRaiseException, MyRaiseException);
    DetourDetach(&(PVOID&)TrueSetUnhandledExceptionFilter, MyUnhandledExceptionFilter);
    DetourDetach(&(PVOID&)TrueAddVectoredExceptionHandler, MyAddVectoredExceptionHandler);

    DetourDetach(&(PVOID&)OriginalEnterCriticalSection, MyEnterCriticalSection);
    DetourDetach(&(PVOID&)OriginalLeaveCriticalSection, MyLeaveCriticalSection);
    DetourDetach(&(PVOID&)OriginalWaitForSingleObject, MyWaitForSingleObject);
    DetourDetach(&(PVOID&)OriginalReleaseMutex, MyReleaseMutex);
    DetourDetach(&(PVOID&)OriginalReleaseSemaphore, MyReleaseSemaphore);

    //S+
    DetourDetach(&(PVOID&)CDetour::Real_TargetPut, *(PBYTE*)&pfMinePut);
    DetourDetach(&(PVOID&)Real_GETQ, Hooked_GETQ);
    DetourDetach(&(PVOID&)Real_PUTQ, Hooked_PUTQ);
    if (Real_SetInternalDipQueueEntries != nullptr) 
    {
        DetourDetach(&(PVOID&)Real_SetInternalDipQueueEntries, My_SetInternalDipQueueEntries);
    }

    // DETACH HERE YOUR CUSTOM HOOK

    DetourDetach(&(PVOID&)Real_RegOpenKeyExA, Hooked_RegOpenKeyExA);
    DetourDetach(&(PVOID&)Real_RegOpenKeyExW, Hooked_RegOpenKeyExW);
    DetourDetach(&(PVOID&)Real_RegQueryValueExA, Hooked_RegQueryValueExA);
    DetourDetach(&(PVOID&)Real_RegQueryValueExW, Hooked_RegQueryValueExW);


    ///////////////////////////////

    
    return DetourTransactionCommit();
}

LONG AttachDetours(VOID)
{
    return HookFunctions();
}

LONG DetachDetours(VOID)
    {
    return DeHookFunctions();
}

//
//////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////// Logging System.
//
static BOOL s_bLog = 1;
static LONG s_nTlsIndent = -1;
static LONG s_nTlsThread = -1;
static LONG s_nThreadCnt = 0;

VOID _PrintEnter(const CHAR* psz, ...)
        {
    DWORD dwErr = GetLastError();  // Preserve the last error code

    LONG nIndent = 0;
    LONG nThread = 0;

    // Retrieve and increment indentation level from thread-local storage
    if (s_nTlsIndent >= 0) {
        nIndent = (LONG)(LONG_PTR)TlsGetValue(s_nTlsIndent);
        TlsSetValue(s_nTlsIndent, (PVOID)(LONG_PTR)(nIndent + 1));
        }

    // Retrieve thread ID from thread-local storage
    if (s_nTlsThread >= 0) {
        nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread);
    }

    if (s_bLog && psz) {
        CHAR szBuf[1024];
        PCHAR pszBuf = szBuf;
        PCHAR pszEnd = szBuf + ARRAYSIZE(szBuf) - 1;

        // Calculate indentation length (max 70 spaces)
        LONG nLen = (nIndent > 0) ? (nIndent < 35 ? nIndent * 2 : 70) : 0;

        // Format: [ProcessID]-[ThreadID] 
        *pszBuf++ = (CHAR)('0' + ((dwProcessId / 10000) % 10));
        *pszBuf++ = (CHAR)('0' + ((dwProcessId / 1000) % 10));
        *pszBuf++ = (CHAR)('0' + ((dwProcessId / 100) % 10));
        *pszBuf++ = (CHAR)('0' + ((dwProcessId / 10) % 10));
        *pszBuf++ = (CHAR)('0' + ((dwProcessId / 1) % 10));
        *pszBuf++ = '-';
        *pszBuf++ = (CHAR)('0' + ((nThread / 100) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 10) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 1) % 10));
        *pszBuf++ = ' ';

        // Add indentation spaces
        while (nLen-- > 0 && pszBuf < pszEnd) {
            *pszBuf++ = ' ';
        }

        // Copy the format string into the buffer
        va_list args;
        va_start(args, psz);

        while ((*pszBuf++ = *psz++) != 0 && pszBuf < pszEnd) {
            // Copy characters
        }

        *pszEnd = '\0';  // Ensure null-termination

        // Log the message
        SyelogV(SYELOG_SEVERITY_INFORMATION, szBuf, args);

        va_end(args);
    }

    SetLastError(dwErr);  // Restore the original error code
}

VOID _PrintExit(const CHAR *psz, ...)
        {
    DWORD dwErr = GetLastError();

    LONG nIndent = 0;
    LONG nThread = 0;
    if (s_nTlsIndent >= 0) {
        nIndent = (LONG)(LONG_PTR)TlsGetValue(s_nTlsIndent) - 1;
        ASSERT(nIndent >= 0);
        TlsSetValue(s_nTlsIndent, (PVOID)(LONG_PTR)nIndent);
    }
    if (s_nTlsThread >= 0) {
        nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread);
    }

    if (s_bLog && psz) {
        CHAR szBuf[1024];
        PCHAR pszBuf = szBuf;
        PCHAR pszEnd = szBuf + ARRAYSIZE(szBuf) - 1;

        // Calculate indentation length (max 70 spaces)
        LONG nLen = (nIndent > 0) ? (nIndent < 35 ? nIndent * 2 : 70) : 0;

        // Format: [ProcessID]-[ThreadID] 
        *pszBuf++ = (CHAR)('0' + ((dwProcessId / 10000) % 10));
        *pszBuf++ = (CHAR)('0' + ((dwProcessId / 1000) % 10));
        *pszBuf++ = (CHAR)('0' + ((dwProcessId / 100) % 10));
        *pszBuf++ = (CHAR)('0' + ((dwProcessId / 10) % 10));
        *pszBuf++ = (CHAR)('0' + ((dwProcessId / 1) % 10));
        *pszBuf++ = '-';
        *pszBuf++ = (CHAR)('0' + ((nThread / 100) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 10) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 1) % 10));
        *pszBuf++ = ' ';
        while (nLen-- > 0) {
            *pszBuf++ = ' ';
        }

        va_list  args;
        va_start(args, psz);

        while ((*pszBuf++ = *psz++) != 0 && pszBuf < pszEnd) {
            // Copy characters.
        }
        *pszEnd = '\0';
        SyelogV(SYELOG_SEVERITY_INFORMATION,
                szBuf, args);

        va_end(args);
    }
    SetLastError(dwErr);
}

VOID _Print(const CHAR *psz, ...)
            {
    DWORD dwErr = GetLastError();

    LONG nIndent = 0;
    LONG nThread = 0;
    if (s_nTlsIndent >= 0) {
        nIndent = (LONG)(LONG_PTR)TlsGetValue(s_nTlsIndent);
            }
    if (s_nTlsThread >= 0) {
        nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread);
        }

    if (s_bLog && psz) {
        CHAR szBuf[1024];
        PCHAR pszBuf = szBuf;
        PCHAR pszEnd = szBuf + ARRAYSIZE(szBuf) - 1;
        LONG nLen = (nIndent > 0) ? (nIndent < 35 ? nIndent * 2 : 70) : 0;
        *pszBuf++ = (CHAR)('0' + ((nThread / 100) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 10) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 1) % 10));
        *pszBuf++ = ' ';
        while (nLen-- > 0) {
            *pszBuf++ = ' ';
    }

        va_list  args;
        va_start(args, psz);

        while ((*pszBuf++ = *psz++) != 0 && pszBuf < pszEnd) {
            // Copy characters.
}
        *pszEnd = '\0';
        SyelogV(SYELOG_SEVERITY_INFORMATION,
                szBuf, args);

        va_end(args);
    }

    SetLastError(dwErr);
}

VOID AssertMessage(CONST PCHAR pszMsg, CONST PCHAR pszFile, ULONG nLine)
{
    Syelog(SYELOG_SEVERITY_FATAL,
           "ASSERT(%s) failed in %s, line %d.\n", pszMsg, pszFile, nLine);
}

//////////////////////////////////////////////////////////////////////////////
//
// DLL module information
//
BOOL ThreadAttach(HMODULE hDll)
{
    (void)hDll;

    if (s_nTlsIndent >= 0) {
        TlsSetValue(s_nTlsIndent, (PVOID)0);
    }
    if (s_nTlsThread >= 0) {
        LONG nThread = InterlockedIncrement(&s_nThreadCnt);
        TlsSetValue(s_nTlsThread, (PVOID)(LONG_PTR)nThread);
    }
    return TRUE;
}

BOOL ThreadDetach(HMODULE hDll)
    {
    (void)hDll;

    (void)hDll;

    if (s_nTlsIndent >= 0) {
        TlsSetValue(s_nTlsIndent, (PVOID)0);
    }
    if (s_nTlsThread >= 0) {
        TlsSetValue(s_nTlsThread, (PVOID)0);
}
    return TRUE;
}

BOOL ProcessAttach(HMODULE hDll)
{
    s_bLog = FALSE;
    s_nTlsIndent = TlsAlloc();
    s_nTlsThread = TlsAlloc();

    WCHAR wzExeName[MAX_PATH];
    s_hInst = hDll;

    GetModuleFileNameW(hDll, s_wzDllPath, ARRAYSIZE(s_wzDllPath));
    GetModuleFileNameW(NULL, wzExeName, ARRAYSIZE(wzExeName));


    char narrowStr[MAX_PATH]; // Make sure this is large enough

    int result = WideCharToMultiByte(
        CP_UTF8,            // Code page (UTF-8)
        0,                  // Flags
        wzExeName,            // Wide string input
        -1,                 // Null-terminated input
        narrowStr,          // Output buffer
        sizeof(narrowStr),  // Size of output buffer
        nullptr,            // Default char (if needed)
        nullptr             // Used default char flag
    );

    std::string appAndLibrary = std::string(narrowStr) + std::string(" - ") + std::string("trcuti" DETOURS_STRINGIFY(DETOURS_BITS));

    SyelogOpen(appAndLibrary.c_str(), SYELOG_FACILITY_APPLICATION);
    Syelog(SYELOG_SEVERITY_INFORMATION,
           "##################################################################\n");
    Syelog(SYELOG_SEVERITY_INFORMATION,
           "### %ls\n", wzExeName);
    LONG error = AttachDetours();
    if (error != NO_ERROR) {
        Syelog(SYELOG_SEVERITY_FATAL, "### Error attaching detours: %d\n", error);
    }

    ThreadAttach(hDll);

    s_bLog = TRUE;
    return TRUE;
}

BOOL ProcessDetach(HMODULE hDll)
    {
    ThreadDetach(hDll);
    s_bLog = FALSE;

    LONG error = DetachDetours();
    if (error != NO_ERROR) {
        Syelog(SYELOG_SEVERITY_FATAL, "### Error detaching detours: %d\n", error);
    }

    Syelog(SYELOG_SEVERITY_NOTICE, "### Closing.\n");
    SyelogClose(FALSE);

    if (s_nTlsIndent >= 0) {
        TlsFree(s_nTlsIndent);
}
    if (s_nTlsThread >= 0) {
        TlsFree(s_nTlsThread);
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void ATTACH_Command() 
{
    InitTable();
    if (attached.exchange(true)) {
        MessageBoxA(NULL, "ALREADY ATTACHED!", "Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    if (Real_SetInternalDipQueueEntries == nullptr) {
		internalQueue.store(0, std::memory_order_relaxed);
        Real_SetInternalDipQueueEntries = (SetInternalDipQueueEntries_t)DetourFindFunction("Shr1090u64.dll", "?SetInternalDipQueueEntries@shr1090@@YAHHH@Z");
        if (Real_SetInternalDipQueueEntries == nullptr) 
        {
            _Print("CANNOT FIND SetInternalDipQueueEntries FUNCTION!");
        }
    }

    // PUT HERE THE CODE TO LOAD REAL FUNCTION POINTERS

    if (Real_PwTag_Write == nullptr) {
        Real_PwTag_Write = (Real_PwTag_Write_t)DetourFindFunction("CPowerinterop64.dll", "?Write@PwTag@@QEAA_NM_K0PEAVPwTime@@@Z");
        if (Real_PwTag_Write == nullptr)
        {
            _Print("CANNOT FIND PwTag::Write(float value, uint64_t qual, TAGWRITE_OPTIONS dwOptions, PwTime * pTime) FUNCTION!");
        }
    }

    // ************************************************

    BOOL r = ProcessAttach(phModule);
    if (!r) {
        MessageBoxA(NULL, "ATTACH COMMAND FAILED!", "Error", MB_OK | MB_ICONERROR);
    }
    else {
	    START_REPORT_INSIGHTS_Command();
    }
}

extern "C" __declspec(dllexport) void DETACH_Command() 
{
    if (!attached.exchange(false)) {
        MessageBoxA(NULL, "NOT YET ATTACHED!", "Error", MB_OK | MB_ICONERROR);
        return;
}

    BOOL r = ProcessDetach(phModule);
    if (!r) {
        MessageBoxA(NULL, "DETACH COMMAND FAILED!", "Error", MB_OK | MB_ICONERROR);
    }
    else {
        STOP_REPORT_INSIGHTS_Command();
    }
}


BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD dwReason, PVOID lpReserved)
{
	phModule = hModule;
    dwProcessId = GetProcessId(GetCurrentProcess());
    (void)hModule;
    (void)lpReserved;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

	void* routine = nullptr;
    switch (dwReason) {
      case DLL_PROCESS_ATTACH:
          if (!InitSymbols()) {
              OutputDebugStringA("[DbgHelp] Failed to initialize symbols.\n");
          }
          else {
              OutputDebugStringA("[DbgHelp] Symbol handler initialized.\n");
          }

        DetourRestoreAfterWith();
        return TRUE;
      case DLL_PROCESS_DETACH:
          if(attached.load()) {
              ProcessDetach(hModule);
		  }
      case DLL_THREAD_ATTACH:
        return ThreadAttach(hModule);
      case DLL_THREAD_DETACH:
        return ThreadDetach(hModule);
    }
    return TRUE;
}
//
///////////////////////////////////////////////////////////////// End of File.