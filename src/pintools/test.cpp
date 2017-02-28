#include <iostream>
#include <fstream>
#include "pin.H"
#include <bitset>
#include <string>
#include <iomanip>
#include <map>
#include <list>

#define TAINT_ARRAY_SIZE 50
#define FLAGS_REG_INDEX  25
bool flag = true;
ofstream RegValuesFile; 
int instr_count = 0;

char taint_array[TAINT_ARRAY_SIZE];
std::map<ADDRINT, std::string>      disAssemblyMap;
std::map<ADDRINT, std::string>      categoryMap;
std::map<ADDRINT, std::string>      mnemonicMap;
std::map<ADDRINT, REG>              writeRegMap;
std::map<REG, std::string>          regNameMap;
std::map<ADDRINT, std::list<REG> > readRegMap;


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
bool can_overflow(ADDRINT ip) {
    if (categoryMap[ip] != "BINARY")
        return false;
    if (mnemonicMap[ip] == "CMP")
        return false;
    return true;
}

void print_flags(REG flags) {
    int f = flags;
    for (int i=0; i<64; i++) {
        if (f & 1)
            RegValuesFile << "1";
        else
            RegValuesFile << "0";
        f >>= 1;
    }
}

void print_taint_array(bool taint) {
    RegValuesFile << (taint ? "TAINT " : "      ");

    char c;
    for (int i=0; i<TAINT_ARRAY_SIZE; i++) {
        switch (taint_array[i]) {
            case 0: RegValuesFile << " . ";
                    break;
            case 1: RegValuesFile << regNameMap[(REG)i];
                    break;
            case 2: RegValuesFile << regNameMap[(REG)i];
                    break;
        }
    }
    RegValuesFile << endl;
}

void print_ins(ADDRINT ip, REG flags){
    RegValuesFile << std::left << std::setw(15) << std::hex << ip << " " << std::setw(10) << categoryMap[ip] << " " << std::setw(40) << disAssemblyMap[ip] << "; ";
    //RegValuesFile << (taint ? "OF " : "   ");

    //print_flags(flags);
}

VOID taint(ADDRINT ip, INS ins, REG flags) { 
    print_ins(ip, flags);

    // in case nothing is written to a register, return
    if (writeRegMap.count(ip) == 0) {
        print_taint_array(false);
        return;
    }

    // write to this
    REG write_reg = writeRegMap[ip];

    // if an overflow occured, taint the array at write_reg and return
    bool taint = false;
    if (can_overflow(ip))
        taint = get_bit(flags, 11);
    if (taint) {
        taint_array[write_reg] = 1;
        print_taint_array(true);
        return;
    }
    


    // in case the taint didn't happen, either due to the op not being able to cause the overflow, 
    // or if the overflow did not happen, check if any of the operands were tainted and taint the result
    const UINT32 max_r = INS_MaxNumRRegs(ins); 
    taint = false;

    std::list<REG>::iterator it;
    for(it = readRegMap[ip].begin(); it != readRegMap[ip].end(); ++it) {
        REG read = *it;
        if (taint_array[read] != 0)
            taint = true;
    }
    taint_array[write_reg] = taint ? 2 : 0;

    print_taint_array(false);
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

    ADDRINT addr = INS_Address(ins);
    disAssemblyMap[addr] = INS_Disassemble(ins);
    categoryMap[addr]    = CATEGORY_StringShort(INS_Category(ins));
    mnemonicMap[addr]    = INS_Mnemonic(ins);
    // get the write register, get the original from it, and check if it is general purpose
    REG write_to = INS_RegW(ins, 0);
    write_to = REG_FullRegName(write_to); // (EAX, AX, AH, AL) -> RAX
    regNameMap[write_to] = REG_StringShort(write_to);
    if (REG_is_gr(write_to))
        writeRegMap[addr] = write_to;

    // filling read registers
    std::list<REG> readList;
    std::list<REG>::iterator it;
    it = readList.begin();

    const UINT32 max_r = INS_MaxNumRRegs(ins); 
    for (unsigned int i=0; i<max_r; i++) {
        REG read = INS_RegR(ins, i);
        if (REG_is_gr(REG_FullRegName(read))) // just the general purpose registers
            readRegMap[addr].insert(it, REG_FullRegName(read));
    }
    readRegMap[addr] = readList;

    if (INS_HasFallThrough(ins)) // FIXME
        INS_InsertCall(ins, IPOINT_AFTER, //this might be IPOINT_AFTER, we might need to check FLAGS after ins execution done 
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

