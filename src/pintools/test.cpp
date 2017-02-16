#include <iostream>
#include <fstream>
#include "pin.H"
#include <bitset>
#include <string>

bool flag = true;
ofstream RegValuesFile; 
ofstream RegNamesFile; 
int instr_count = 0;

VOID printReg(REG reg, ADDRINT value, INS ins) { 
    RegValuesFile << instr_count++ << ": " << REG_StringShort(reg) << " = " << value << "; " << INS_Disassemble(ins) << endl;
}


VOID Instruction(INS ins, VOID *v)
{
    const UINT32 max_w=INS_MaxNumWRegs(ins);//number of written registers in the instruction

    if(flag){    // initialize taint array for just once

        RegValuesFile.open("logs/values.out");
        RegNamesFile.open("logs/names.out");

        flag=false;
    }

    for(UINT32 i=0; i<max_w; i++){
        REG writeReg = INS_RegW(ins, i);
        string writeRegName = REG_StringShort(writeReg);
        //RegValuesFile << writeRegName << endl;
        //ADDRINT addr = INS_Address(ins);
        
        
        if (writeRegName.substr(1, 2) != "mm")
            INS_InsertCall(ins, IPOINT_BEFORE, //this might be IPOINT_AFTER, we might need to check FLAGS after ins execution done 
                (AFUNPTR)printReg,
                IARG_UINT32, REG(INS_OperandReg(ins, i)),
                IARG_REG_VALUE, INS_RegW(ins, 0),
                IARG_UINT32, ins,
                IARG_END);

    }
}

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    RegValuesFile.setf(ios::showbase);
    RegNamesFile.setf(ios::showbase);

    RegValuesFile.close();
    RegNamesFile.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */


INT32 Usage()
{
    cerr << "This tool counts the number of dynamic instructions executed" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}

