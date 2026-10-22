// Shared helpers for the experiments' logic files (E2 registry_fidelity, E3 guardrail, E5 filedeny): the object
// name and root handle of the OBJECT_ATTRIBUTES argument of the ntdll open/create functions.
//
// Include it after <winternl.h>. CopyUnicodeString is defined by templates/_user_logic_helpers.cpp before the
// logic file is included in the generated hook source.
//
// transpiler.py parses the logic file with libclang from the build folder, where this relative include does not
// resolve. That is harmless: only the signatures block and the pre/post-hook declarations are extracted, and
// MSVC resolves the include relative to the logic file.

#include <cstdint>
#include <string>

// Object name of an OBJECT_ATTRIBUTES (relative to RootDirectory when RootDirectory != NULL).
// Passed explicitly in log formats: struct pointers are not dereferenced by the type analysis.
static std::string CopyObjectName(const OBJECT_ATTRIBUTES* source, size_t maxChars = 512) {
    if (!source) return "null";
    return CopyUnicodeString(source->ObjectName, maxChars);
}

// RootDirectory handle of an OBJECT_ATTRIBUTES, as an integer for hex formatting
static uintptr_t ObjectRoot(const OBJECT_ATTRIBUTES* source) {
    if (!source) return 0;
    return (uintptr_t)source->RootDirectory;
}
