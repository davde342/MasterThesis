#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>   // NTSTATUS, OBJECT_ATTRIBUTES, IO_STATUS_BLOCK, NtCreateFile, NtOpenFile

#include <cstring>
#include <fstream>
#include <string>


#include "../../suite/cpp/hd_paths.h"

//
// Matching compares the final component of the name as passed (ObjectName) with each entry, ignoring case as
// NTFS does. Only the final component, because a relative open arrives relative to a directory handle
// (RootDirectory): CreateFileW(L"files\\x.txt") reaches NtCreateFile as "files\x.txt" relative to the current
// directory handle, so the full path is not in the name.
//
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)

// @signatures-start
NTSTATUS NTAPI NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
NTSTATUS NTAPI NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
// @signatures-end

// The names the process cannot open, one per line, written by file_deny_mt/run.py into the target's working folder. The list
// names itself, so the process cannot open it either.
//
// The pre-hook reads the list on every call. The read is a file open made inside a hook function, so it reaches
// NtCreateFile again on the same thread, where the re-entrancy guard (t_InHook) sends it straight to the original
// function. Without the guard, the read would run this pre-hook again, which would read the list again, until the
// stack overflows. On every call, not once: a thread's first call is a CreateFileW, whose nested read re-enters
// NtCreateFile's own hook, which Frida-Gum's dispatcher skips by itself. The reads made from the NtOpenFile hook reach
// the hook function of NtCreateFile with both engines. If a read went through that hook function, it would be denied,
// because the list names itself.
static const char kListFile[] = "denylist.txt";

// Pre-hook of NtCreateFile / NtOpenFile (same parameter name in both): true = allow
// @CheckFileAllowed-start
static bool CheckFileAllowed(POBJECT_ATTRIBUTES ObjectAttributes) {
    if (!ObjectAttributes) return true;
    std::ifstream list(kListFile);
    if (!list) return false;  // the list cannot be read: deny the call (fail closed)
    const std::string name = CopyObjectName(ObjectAttributes);
    const size_t slash = name.find_last_of('\\');
    const char* file = name.c_str() + (slash == std::string::npos ? 0 : slash + 1);
    for (std::string denied; std::getline(list, denied);) {
        if (!denied.empty() && _stricmp(file, denied.c_str()) == 0) return false;
    }
    return true;
}
