#include "frida-gum.h"
#include <windows.h>

typedef void (* ProcessTaskFunc) (int taskId, const char * taskType, int complexity);
typedef void (* LogTaskResultFunc) (int taskId, const char * status, double result);

static ProcessTaskFunc true_process_task = NULL;
static LogTaskResultFunc true_log_task_result = NULL;

static GumInterceptor * interceptor = NULL;

// Target function entry points to revert on detach
static gpointer target_process_task = NULL;
static gpointer target_log_task_result = NULL;

static volatile LONG g_task_count = 0;
static volatile LONG g_modified_count = 0;
static gboolean g_hooks_attached = FALSE;

static CRITICAL_SECTION console_lock;

static void HookedProcessTask (int taskId, const char * taskType, int complexity)
{
  InterlockedIncrement (&g_task_count);

  int modifiedComplexity = complexity;
  gboolean modified = FALSE;

  if (complexity > 500)
  {
    modifiedComplexity = 100;
    InterlockedIncrement (&g_modified_count);
    modified = TRUE;
  }

  EnterCriticalSection (&console_lock);
  g_print ("[HOOK ProcessTask] TID: %lu | Task ID: %d | Type: %s | Original Complexity: %dms",
           GetCurrentThreadId (), taskId, taskType, complexity);
  if (modified)
  {
    g_print (" | Reduced to %dms", modifiedComplexity);
  }
  g_print ("\n");
  LeaveCriticalSection (&console_lock);

  true_process_task (taskId, taskType, modifiedComplexity);
}

static void HookedLogTaskResult (int taskId, const char * status, double result)
{
  EnterCriticalSection (&console_lock);
  g_print ("[HOOK LogTaskResult] TID: %lu | Task ID: %d | Status: %s | Result: %.2f | Stats: [Intercepted: %ld, Modified: %ld]\n",
           GetCurrentThreadId (), taskId, status, result, g_task_count, g_modified_count);
  LeaveCriticalSection (&console_lock);

  true_log_task_result (taskId, status, result);
}

static void AttachHooks (void)
{
  gum_init_embedded ();
  interceptor = gum_interceptor_obtain ();

  InitializeCriticalSection (&console_lock);

  HMODULE hExe = GetModuleHandle (NULL);
  if (hExe == NULL)
  {
    g_print ("[HOOK] Failed to resolve main module handle\n");
    return;
  }

  target_process_task = (gpointer) GetProcAddress (hExe, "ProcessTask");
  target_log_task_result = (gpointer) GetProcAddress (hExe, "LogTaskResult");

  if (target_process_task == NULL || target_log_task_result == NULL)
  {
    g_print ("[HOOK] Failed to resolve target functions\n");
    return;
  }

  gum_interceptor_begin_transaction (interceptor);

  // Replace target functions with hooks. We use replace instead of attach
  // to correctly match the floating-point (double) argument of LogTaskResult
  // (which is passed via XMM registers).
  gum_interceptor_replace (interceptor,
                           target_process_task,
                           (gpointer) HookedProcessTask,
                           NULL,
                           (gpointer *) &true_process_task);

  gum_interceptor_replace (interceptor,
                           target_log_task_result,
                           (gpointer) HookedLogTaskResult,
                           NULL,
                           (gpointer *) &true_log_task_result);

  gum_interceptor_end_transaction (interceptor);

  g_hooks_attached = TRUE;
  g_print ("Hooks attached\n");
}

static void DetachHooks (void)
{
  if (!g_hooks_attached)
    return;

  g_print ("Detaching hooks\n");

  gum_interceptor_begin_transaction (interceptor);

  if (target_process_task != NULL)
    gum_interceptor_revert (interceptor, target_process_task);

  if (target_log_task_result != NULL)
    gum_interceptor_revert (interceptor, target_log_task_result);

  gum_interceptor_end_transaction (interceptor);

  // Safety loop: wait until all threads have left the hook callbacks/trampolines using Frida-Gum's flush API.
  while (!gum_interceptor_flush (interceptor))
  {
    Sleep (5);
  }

  DeleteCriticalSection (&console_lock);

  g_print ("Hooks detached\n");
  g_hooks_attached = FALSE;

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
      DisableThreadLibraryCalls (hModule);
      AttachHooks ();
      break;

    case DLL_PROCESS_DETACH:
      DetachHooks ();
      break;
  }

  return TRUE;
}
