#include <iostream>
#include <fstream>
#include "pin.H"
#include <bitset>
#include <string>
#include <iomanip>

#define TAINT_ARRAY_SIZE 100
#define FLAGS_REG_INDEX  25

bool flag = true;
ofstream RegValuesFile; 
ofstream RegNamesFile; 
int instr_count = 0;

int get_bit(int value, int n) {
    // returns nonzero value if the nth bit is set
    // input n is zero-indexed
    return (int) (value & (1 << n));
}

VOID printReg(UINT64 addr, REG reg, ADDRINT value, INS ins) { 
    RegValuesFile << std::left << std::setw(16) << addr 
                  << ": " << std::setw(32) << INS_Disassemble(ins) << "; " 
                  << std::setw(6) << REG_StringShort(reg) << " = " << std::setw(20) << value;

    if (REG_StringShort(reg).compare("rflags") == 0 && get_bit(value, 11))
        RegValuesFile << " OVERFLOW!" << endl;
    else
        RegValuesFile << endl;
}

bool taint1_policy(INS ins, bool reg1_taint) {
    return reg1_taint;
}

bool taint2_policy(INS ins, bool reg1_taint, bool reg2_taint) {
    return reg1_taint || reg2_taint;
}

// taint2 is inserted before operations with two arguments
//
VOID taint(INS ins, REG flags, int *taint_array) { 
    //bool taint = get_bit(flags, 11);

    RegValuesFile << flags << endl;

    //if (taint)
        //taint_array[reg] = taint;
    //else {
        //const UINT32 max_r = INS_MaxNumRRegs(ins); 
        //const UINT32 max_w = INS_MaxNumWRegs(ins);
    
        //if (max_r == 2) {
            //REG read1 = INS_RegR(ins, 0);
            //REG read2 = INS_RegR(ins, 1);
            //REG write = INS_RegW(ins, 0);

            //taint = taint2_policy(taint_array[read1], taint_array[read2]);
            //taint_array[write] = taint;
        //}
    //}
}


VOID Instruction(INS ins, VOID *v)
{
    //const UINT32 max_r=INS_MaxNumRRegs(ins);//number of readed registers in the instruction
    const UINT32 max_w=INS_MaxNumWRegs(ins);//number of written registers in the instruction

    bool taint_array[TAINT_ARRAY_SIZE];

    if(flag){    // initialize taint array for just once

        RegValuesFile.open("logs/values.out");
        RegNamesFile.open("logs/names.out");

        for (int i=0; i<TAINT_ARRAY_SIZE; i++)
            taint_array[i] = i%2;

        flag=false;
    }

    for(UINT32 i=0; i<max_w; i++){
        REG writeReg = INS_RegW(ins, i);
        string writeRegName = REG_StringShort(writeReg);
        
        if (writeRegName.substr(1, 2) != "mm")
            //INS_InsertCall(ins, IPOINT_BEFORE, //this might be IPOINT_AFTER, we might need to check FLAGS after ins execution done 
                //(AFUNPTR)printReg,
                //IARG_INST_PTR,
                //IARG_UINT32, writeReg,
                //IARG_REG_VALUE, writeReg,
                //IARG_UINT32, ins,
                //IARG_END);
            INS_InsertCall(ins, IPOINT_BEFORE, //this might be IPOINT_AFTER, we might need to check FLAGS after ins execution done 
                (AFUNPTR) taint,
                IARG_UINT32, ins,
                IARG_REG_VALUE, FLAGS_REG_INDEX,
                IARG_PTR, taint_array,
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
