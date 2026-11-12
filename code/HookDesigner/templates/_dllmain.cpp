// DLL Entrypoint
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
#ifdef HOOK_DLLMAIN_ATTACH_PRECHECK
    HOOK_DLLMAIN_ATTACH_PRECHECK();
#endif

    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            break;
        case DLL_PROCESS_DETACH:
            {% if telemetry and telemetry.metrics == "prometheus" %}
            // Process exit (lpReserved non-NULL) with the hooks still installed: the other threads, those of the
            // metrics server included, have already ended. The destructor of g_PromExposer, which the CRT runs right
            // after this function, would wait for them forever under the loader lock. Release it without stopping it:
            // the OS frees what it holds. Ejection (FreeLibrary, lpReserved NULL) has already reset it.
            if (lpReserved) {
                g_PromExposer.release();
            }
            {% endif %}
            break;
    }
    return TRUE;
}
