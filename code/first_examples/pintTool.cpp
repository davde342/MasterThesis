#include "pin.H"
#include <fstream>
#include <iostream>

using namespace std;

ostream *out;

KNOB<string> knob_outfile(KNOB_MODE_WRITEONCE, "pintool", "o", "branch_log.txt", "output filename");

// Analysis function (Runs at execution time)
void record_branch(ADDRINT instruction_address, ADDRINT target_address, BOOL taken)
{
    *out << "Branch at 0x" << hex << instruction_address;
    
    if (taken) {
        *out << " -> TAKEN (Jumped to 0x" << target_address << ")" << endl;
    } else {
        *out << " -> NOT TAKEN (Fell through)" << endl;
    }
}


// Instrumentation function (Runs at compilation time)
void trace(INS instruction, void *v)
{
    //Filter ntdll.dll and kernel32.dll
    RTN rtn = INS_Rtn(instruction);
    if (RTN_Valid(rtn)) {
        SEC sec = RTN_Sec(rtn);
        if (SEC_Valid(sec)) {
            IMG img = SEC_Img(sec);
            if (IMG_Valid(img) && IMG_IsMainExecutable(img)) {
                
                // If it is inside the target executable, check if it's an IF branch
                if (INS_IsBranch(instruction) && INS_HasFallThrough(instruction)) {
                    
                    // Inject analysis function right before the jump happens
                    INS_InsertCall(instruction, IPOINT_BEFORE, (AFUNPTR)record_branch,
                                   IARG_INST_PTR,           
                                   IARG_BRANCH_TARGET_ADDR,  
                                   IARG_BRANCH_TAKEN,        
                                   IARG_END);
                }
            }
        }
    }
}


void fini(INT32 code, void *v)
{
    *out << "Instrumentation finished." << endl;
    delete out; 
}

int main(int argc, char *argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
        return 1; 

    out = new ofstream(knob_outfile.Value().c_str());

    INS_AddInstrumentFunction(trace, 0); 
    PIN_AddFiniFunction(fini, 0);        
    
    PIN_StartProgram();                  
    
    return 0;
}