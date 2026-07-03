#include "{{ logic_file_rel }}"

// Inner helper under SEH protection to copy string without instantiating C++ objects
static bool CopyStringImpl(const char* source, char* dest, size_t maxChars) {
    __try {
        for (size_t i = 0; i < maxChars; ++i) {
            char c = source[i];
            dest[i] = c;
            if (c == '\0') {
                return true;
            }
        }
        dest[maxChars] = '\0';
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// copy wrapper with std::string allocation
static std::string CopyString(const char* source, size_t maxChars = 128) {
    if (!source) {
        return "null";
    }
    std::vector<char> buffer(maxChars + 1, 0);
    if (CopyStringImpl(source, buffer.data(), maxChars)) {
        return std::string(buffer.data());
    }
    return "<INVALID_MEMORY>";
}

// Inner helper under SEH protection to dereference pointer without instantiating C++ objects
template <typename T>
static bool ReadPointerImpl(const T* ptr, T& outVal) {
    __try {
        outVal = *ptr;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Outer read wrapper
template <typename T>
static T ReadPointer(const T* ptr, T fallback = T()) {
    if (!ptr) {
        return fallback;
    }
    T val = fallback;
    if (ReadPointerImpl(ptr, val)) {
        return val;
    }
    return fallback;
}

// Helper to log SEH exceptions to avoid C2712 compiler errors in __try/__except functions
static void LogSEHException(const char* logicName, const char* functionName, DWORD exceptionCode) {
    std::ostringstream ss;
    ss << "[CRITICAL SCADA HOOK] SEH Exception 0x" << std::hex << exceptionCode << std::dec 
       << " caught in " << logicName << " of " << functionName << std::endl;
    std::cerr << ss.str();
}

// Using set for avoiding double definition in case of shared pre/post logic
{% set generated_pre_hooks = [] %}
{% set generated_post_hooks = [] %}
{% for hook in hooks %}
{% if hook.behaviors.security_policy.pre_hook and hook.behaviors.security_policy.pre_hook not in generated_pre_hooks %}
{% set _ = generated_pre_hooks.append(hook.behaviors.security_policy.pre_hook) %}
bool RunPreLogic_{{ hook.behaviors.security_policy.pre_hook }}({%- for param in hook.behaviors.security_policy.pre_hook_params -%}{{ param.type }} {{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%}) {
    __try {
        {{ hook.behaviors.security_policy.pre_hook }}({%- for param in hook.behaviors.security_policy.pre_hook_params -%}{{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        LogSEHException("pre_logic", "{{ hook.behaviors.security_policy.pre_hook }}", GetExceptionCode());
        return false;
    }
}
{% endif %}

{% if hook.behaviors.security_policy.post_hook and hook.behaviors.security_policy.post_hook not in generated_post_hooks %}
{% set _ = generated_post_hooks.append(hook.behaviors.security_policy.post_hook) %}
bool RunPostLogic_{{ hook.behaviors.security_policy.post_hook }}({%- for param in hook.behaviors.security_policy.post_hook_params -%}{{ param.type }} {{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%}) {
    __try {
        {{ hook.behaviors.security_policy.post_hook }}({%- for param in hook.behaviors.security_policy.post_hook_params -%}{{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        LogSEHException("post_logic", "{{ hook.behaviors.security_policy.post_hook }}", GetExceptionCode());
        return false;
    }
}
{% endif %}
{% endfor %}
