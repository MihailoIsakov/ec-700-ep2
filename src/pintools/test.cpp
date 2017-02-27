#include <iostream>
#include <fstream>
#include "pin.H"
#include <bitset>
#include <string>
#include <iomanip>
#include <map>

#define TAINT_ARRAY_SIZE 100
#define FLAGS_REG_INDEX  25
bool flag = true;
ofstream RegValuesFile; 
int instr_count = 0;

bool taint_array[TAINT_ARRAY_SIZE];
std::map<ADDRINT, std::string> disAssemblyMap;
std::map<ADDRINT, std::string> categoryMap;


int get_bit(int value, int n) {
    // returns nonzero value if the nth bit is set
    // input n is zero-indexed
    return (int) (value & (1 << n)) != 0;
}

bool taint1_policy(INS ins, bool reg1_taint) {
    return reg1_taint;
}

// The taint propagation policy for instructions with two register operands
bool taint2_policy(INS ins, bool reg1_taint, bool reg2_taint) {
    return reg1_taint || reg2_taint;
}

// checks if the instruction producting the overflow should be regarded,
// as some instructions commonly produce OF that is useless (MOV, JZ)
// We are interested in arithmetic operations, 
// excluding CMP which performs subtractions causing OFs
bool can_overflow(INS ins) {
    if (CATEGORY_StringShort(INS_Category(ins)) != "BINARY")
        return false;
    if (INS_Mnemonic(ins) == "CMP")
        return false;
    return true;
}

// TODO add check if flags is being written to in this instruction
VOID taint(ADDRINT ip, INS ins, REG flags) { 

    bool taint = false;
    if (can_overflow(ins))
        taint = get_bit(flags, 11);

    //if (taint) {
        //REG write_to = INS_RegW(ins, 0);
        //write_to = REG_FullRegName(write_to); // (EAX, AX, AH, AL) -> RAX

        //if (REG_is_gr(write_to))
            //taint_array[write_to] = taint;
    //}
    //else {
        //// depending on the number of operands, use different propagation function
        //const UINT32 max_r = INS_MaxNumRRegs(ins); 
    
        //switch(max_r) {
            //case 1: {
                //REG read = INS_RegR(ins, 0);
                //taint = taint1_policy(ins, taint_array[read]);
                //if(taint)
                    //cout << "1: "<< INS_Disassemble(ins) << endl;
                //break;
            //}
            //case 2: {
                //REG read1 = INS_RegR(ins, 0);
                //REG read2 = INS_RegR(ins, 1);
                //taint = taint2_policy(ins, taint_array[read1], taint_array[read2]);
                //if(taint)
                    //cout << "2: "<< INS_Disassemble(ins) << endl;
                //break;
            //}
            //default: {
                //break;
            //}
        //}
        
        //REG write = INS_RegW(ins, 0);
        //taint_array[write] = taint;
    //}
    

    RegValuesFile << std::left << ip << " " << std::setw(10) << std::hex << categoryMap[ip] << " " << std::setw(36) << disAssemblyMap[ip] << "; ";
    if (taint)
        RegValuesFile << "OF ";
    else
        RegValuesFile << "   ";
    //for (int i=0; i<TAINT_ARRAY_SIZE; i++)
        //RegValuesFile << taint_array[i];
    int f = flags;
    for (int i=0; i<64; i++) {
        if (f & 1)
            RegValuesFile << "1";
        else
            RegValuesFile << "0";
        f >>= 1;
    }
    //RegValuesFile << "\t";
    //for (int i=0; i<TAINT_ARRAY_SIZE; i++) {
        //RegValuesFile << (taint_array[i] != 0);
    //}
    RegValuesFile << endl;
}


VOID Instruction(INS ins, VOID *v)
{
    //const UINT32 max_r=INS_MaxNumRRegs(ins);//number of readed registers in the instruction
    //const UINT32 max_w=INS_MaxNumWRegs(ins);//number of written registers in the instruction

    if(flag){    // initialize taint array for just once
        flag = false;
        RegValuesFile.open("logs/values.out");
        for (int i=0; i<TAINT_ARRAY_SIZE; i++)
            taint_array[i] = 0;
    }

    disAssemblyMap[INS_Address(ins)] = INS_Disassemble(ins);
    categoryMap[INS_Address(ins)] = CATEGORY_StringShort(INS_Category(ins));
    
    INS_InsertCall(ins, IPOINT_BEFORE, //this might be IPOINT_AFTER, we might need to check FLAGS after ins execution done 
        (AFUNPTR) taint,
        IARG_INST_PTR,
        IARG_UINT32, ins,
        IARG_REG_VALUE, FLAGS_REG_INDEX,
        IARG_END);
}

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    RegValuesFile.setf(ios::showbase);

    RegValuesFile.close();
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

