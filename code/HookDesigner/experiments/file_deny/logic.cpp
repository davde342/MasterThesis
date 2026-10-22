#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>   // NTSTATUS, OBJECT_ATTRIBUTES, IO_STATUS_BLOCK, NtCreateFile, NtOpenFile

#include <cstring>
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

// path components the process cannot open (must match DENYLIST in run.py)
static const char* const kDenylist[] = {"denied_1.txt", "denied_2.txt"};

// Pre-hook of NtCreateFile / NtOpenFile (same parameter name in both): true = allow
// @CheckFileAllowed-start
static bool CheckFileAllowed(POBJECT_ATTRIBUTES ObjectAttributes) {
    if (!ObjectAttributes) return true;
    const std::string name = CopyObjectName(ObjectAttributes);
    const size_t slash = name.find_last_of('\\');
    const char* file = name.c_str() + (slash == std::string::npos ? 0 : slash + 1);
    for (const char* denied : kDenylist) {
        if (_stricmp(file, denied) == 0) return false;
    }
    return true;
}
