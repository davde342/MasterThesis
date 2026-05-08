#include "dr_api.h"
#include "drmgr.h"

static file_t out_file;

// Analysis function (Clean Call)
static void record_branch(app_pc instr_addr, app_pc target_addr, int taken)
{
    if (taken) {
        dr_fprintf(out_file, "Conditional Branch at "PFX" -> taken (Jumped to "PFX")\n", 
instr_addr, target_addr);
    } else {
        dr_fprintf(out_file, "Conditional Branch at "PFX" -> not taken (Fell through)\n", 
                   instr_addr);
    }
}

// Instrumentation function (Runs at JIT compile time)
static dr_emit_flags_t event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb, 
                                         instr_t *inst, bool for_trace, bool translating,
                                         void *user_data)
{
    //Filtering ntdll.dll and kernel32.dll
    app_pc instr_addr = instr_get_app_pc(inst);
    module_data_t *mod = dr_lookup_module(instr_addr);
    bool is_main_exec = false;
    
    if (mod != NULL) {
        module_data_t *main_mod = dr_get_main_module();
        if (main_mod != NULL) {
            // Check if this basic block belongs to main target.exe
            if (mod->start == main_mod->start) {
                is_main_exec = true;
            }
            dr_free_module_data(main_mod);
        }
        dr_free_module_data(mod);
    }

    if (!is_main_exec) {
        return DR_EMIT_DEFAULT;
    }

    // Check if it's a conditional branch (CBR)
    if (instr_is_cbr(inst)) {
        //Inject analysis function
        // It automatically passes (instr_addr, target_addr, taken) to function
        dr_insert_cbr_instrumentation(drcontext, bb, inst, (void *)record_branch);
    }
    
    return DR_EMIT_DEFAULT;
}

void event_exit(void)
{
    dr_fprintf(out_file, "Instrumentation finished.\n");
    dr_close_file(out_file);
    drmgr_exit();
}


DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    if (!drmgr_init())
        DR_ASSERT_MSG(false, "drmgr_init failed!");

    out_file = dr_open_file("branch_log_dynamorio.txt", DR_FILE_WRITE_OVERWRITE);
    dr_fprintf(out_file, "Starting DynamoRIO instrumentation\n");

    if (!drmgr_register_bb_instrumentation_event(NULL, event_bb_analysis, NULL))
        DR_ASSERT_MSG(false, "fail to register event_app_instruction!");
    drmgr_register_exit_event(event_exit);
}