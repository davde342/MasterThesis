// DLL Entrypoint
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    {% if engine == 'detours' %}
    if (DetourIsHelperProcess()) {
        return TRUE;
    }
    {% endif %}

    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
