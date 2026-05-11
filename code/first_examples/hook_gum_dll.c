#include "frida-gum.h"
#include <windows.h>


static GumInterceptor       * interceptor = NULL;
static GumInvocationListener * listener    = NULL;
static GumModule             * user32      = NULL;

static void example_listener_on_enter (GumInvocationContext * ic, gpointer user_data);
static void example_listener_on_leave (GumInvocationContext * ic, gpointer user_data);


static void AttachHooks (void)
{
  gum_init_embedded ();
  interceptor = gum_interceptor_obtain ();
  listener = gum_make_call_listener (example_listener_on_enter,
                                     example_listener_on_leave,
                                     NULL, NULL);

  user32 = gum_process_find_module_by_name ("user32.dll");

  gum_interceptor_begin_transaction (interceptor);
  gum_interceptor_attach (interceptor,
      GSIZE_TO_POINTER (gum_module_find_export_by_name (user32, "MessageBoxW")),
      listener,
      NULL,
      GUM_ATTACH_FLAGS_NONE);
  gum_interceptor_end_transaction (interceptor);

  g_print ("Hooks attached\n");
}

static void DetachHooks (void)
{
  g_print ("Detaching hooks\n");

  gum_interceptor_begin_transaction (interceptor);
  gum_interceptor_detach (interceptor, listener);
  gum_interceptor_end_transaction (interceptor);

  g_object_unref (user32);
  g_object_unref (listener);
  g_object_unref (interceptor);

  gum_deinit_embedded ();

}

// Dll entry point
BOOL APIENTRY DllMain (HMODULE hModule,
                       DWORD   ul_reason_for_call,
                       LPVOID  lpReserved)
{
  switch (ul_reason_for_call)
  {
    case DLL_PROCESS_ATTACH:
      AttachHooks ();
      break;

    case DLL_PROCESS_DETACH:
      DetachHooks ();
      break;
  }

  return TRUE;
}


static void
example_listener_on_enter (GumInvocationContext * ic,
                           gpointer user_data)
{
  // The arguments for MessageBoxW are 0-indexed:
  // 0: HWND hWnd
  // 1: LPCWSTR lpText
  // 2: LPCWSTR lpCaption
  // 3: UINT uType

    guint originalType = GPOINTER_TO_UINT (gum_invocation_context_get_nth_argument (ic, 3));
    
    guint modifiedType = MB_YESNO;

    static const wchar_t* customCaption = L"Hooked, choose:";

    gum_invocation_context_replace_nth_argument (ic, 2, (gpointer) customCaption);
    gum_invocation_context_replace_nth_argument (ic, 3, GUINT_TO_POINTER (modifiedType));
  
}

static void
example_listener_on_leave (GumInvocationContext * ic,
                           gpointer user_data)
{
  int result = GPOINTER_TO_INT (gum_invocation_context_get_return_value (ic));

  if (result == IDNO) 
  {
      g_print ("Intercepted IDNO (No). Changing result to IDYES (Yes)\n");
      gum_invocation_context_replace_return_value (ic, GINT_TO_POINTER (IDYES));
  }
  else if (result == IDYES)
  {
      g_print ("Intercepted IDYES (Yes). Nothing to do\n");
  }
}
