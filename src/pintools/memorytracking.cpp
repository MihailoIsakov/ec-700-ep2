#include <iostream>
#include <fstream>
#include "pin.H"
#include <bitset>
#include <iomanip>
#include <string>
#include <set>
#include <map>
#include <list>

#define TAINT_ARRAY_SIZE 25
#define FLAGS_REG_INDEX  25


// log files
ofstream RegValuesFile; 

// globals
bool flag=true;
bool did_taint=false;

char taint_array[TAINT_ARRAY_SIZE];
std::set<ADDRINT>                  TMS; //tainted memory set
std::map<ADDRINT, REG>             writeRegMap;
std::map<ADDRINT, REG>             secondOperandMap;
std::map<ADDRINT, std::list<REG> > readRegMap;
std::map<ADDRINT, std::string>     disAssemblyMap;
std::map<ADDRINT, std::string>     categoryMap;
std::map<ADDRINT, std::string>     mnemonicMap;
std::map<REG,     std::string>     regNameMap;

ADDRINT writeAddr, readAddr;
bool validReadAddr, validWriteAddr;


int get_bit(int value, int n) {
    // returns nonzero value if the nth bit is set
    // input n is zero-indexed
    return (int) (value & (1 << n)) != 0;
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

    for (int i=0; i<TAINT_ARRAY_SIZE; i++) {
        switch (taint_array[i]) {
            case 0: RegValuesFile << ".   ";
                    break;
            case 1: RegValuesFile << std::setw(4) << regNameMap[(REG)i];
                    break;
            case 2: RegValuesFile << std::setw(4) << regNameMap[(REG)i];
                    break;
        }
    }
}

void print_ins(ADDRINT ip, REG flags){
    RegValuesFile << std::left << std::setw(15) << std::hex << ip << " " << std::setw(10) << categoryMap[ip] << " " << std::setw(40) << disAssemblyMap[ip] << "; ";
    //RegValuesFile << (taint ? "OF " : "   ");

    //print_flags(flags);
}

void print_tainted_addresses() {
    RegValuesFile << "Tainted addr: " ;
    for(std::set<ADDRINT>::iterator it = TMS.begin(); it != TMS.end(); ++it)
        RegValuesFile << *it << ", ";
}

void printESP(REG esp) {
    RegValuesFile << "ESP: " << esp <<"; ";
}

void print_all(ADDRINT ip, REG flags, REG esp) {
    print_ins(ip, flags);
    print_taint_array(did_taint);
    did_taint = false;
    printESP(esp);
    print_tainted_addresses();
    RegValuesFile << endl;
}

/////////////////////////////////////////////////////////////////////////////////
// -----------------------------------------ANALYSIS ROUTINE--------------------
///////////////////////////////////////////////////////////////////////////////////

// BOTH WRITE AND READ
// Saves the tainted memory address to TMS.
// The address is tainted if:
//     1. we are saving a tainted register value
//     2. the operation saving the value has overflowed,
//        and that the operation is classified as having reasonable overflows,
//        (as in the case of an add with the destination in memory)
// Since the same location is being used as an input and a destination, there is no way
// to remove the taint from it, even though the sum result and the register might be clean.
VOID binaryRWAnalysis(INS ins, ADDRINT addr, ADDRINT flag) {
    bool second_taint = false;
    // get the register from the map
    if (secondOperandMap[addr] != REG_INVALID_) {
        second_taint = taint_array[secondOperandMap[addr]];
    }

    bool op_taint = can_overflow(addr) && get_bit(flag, 11);
    did_taint = op_taint;

    if (second_taint || op_taint) {
        TMS.insert(writeAddr);
        cout << "SAVING: " << readAddr << endl;
    }
}

// PUSH analysis code
// The read address is stored in EA
// The write address is stored in sp
// We overwrite sp with the taint value of EA
// example: push qword ptr[rsp+0x58]
VOID pushRWAnalysis(ADDRINT sp) {
    bool taint = TMS.find(readAddr) != TMS.end();

    if (taint) { // add to SP to set
        cout << "pushRW SAVING: " << readAddr << endl;
        TMS.insert(writeAddr);
    }
    else { // otherwise remove it if present
        cout << "pushRW ERASING: " << readAddr << endl;
        TMS.erase(writeAddr);
    }       
}

// MOV writing to memory analysis code
// example: mov qword ptr [reg+reg*scale+displacement], reg
// MOV writes the value stored in a register to memory
// We overwrite the taint of the memory location with the registers taint
VOID movWAnalysis(ADDRINT ip) { 
    bool taint = false;

    if (secondOperandMap[ip] != REG_INVALID_) {
        taint = taint_array[secondOperandMap[ip]];
    }

    if (taint) { // if reg contains an tainted value
        cout << "MOVING TAINT TO: " << writeAddr;
        TMS.insert(writeAddr);
    } 
    else { // if reg is not tainted, remove it.
        cout << "ERASING: " << readAddr;
        TMS.erase(writeAddr);
    }
}

// register PUSH analysis code
// example: PUSH eax
// We overwrite the taint of the memory location with the registers taint
VOID pushWAnalysis(ADDRINT ip, ADDRINT sp) { 
    bool taint = false;

    if (secondOperandMap[ip] != REG_INVALID_) {
        taint = taint_array[secondOperandMap[ip]];
    }

    if (taint) { // if pushed register is tainted; insert addr into set
        cout << "pushWAnalysis SAVING: " << std::hex << sp << endl;
        TMS.insert(sp);
    }
    else { // If pushed register is not tainted, remove that address from RBT.
        cout << "ERASING: " << readAddr << endl;
        TMS.erase(sp);
    }
}

// Operations writing to a register analysis
// For any operation writing to a register, calculates the taint by looking at:
//     1. Taint of register operands
//     2. Taint of read memory address
//     3. Whether the instruction has overflowed and it is regarded as overflowable
VOID taintAnalysis(ADDRINT ip, INS ins, REG flags) { 

    // write to this
    REG write_reg = writeRegMap[ip];

    // if an overflow occured, taint the array at write_reg and return
    bool taint = false;
    if (can_overflow(ip))
        taint = get_bit(flags, 11);
    if (taint) {
        taint_array[write_reg] = 1;
        did_taint = true;
        return;
    }

    // in case the taint didn't happen, either due to the op not being able to cause the overflow, 
    // or if the overflow did not happen, check if any of the operands were tainted and taint the result
    // the operands are registers and a possible memory address
    taint = false;

    // check if any of the registers are tainted
    std::list<REG>::iterator it;
    for(it = readRegMap[ip].begin(); it != readRegMap[ip].end(); ++it) {
        REG read = *it;
        // FIXME: better taint policy?
        if (taint_array[read] != 0)
            taint = true;
    }

    // check if the memory address is tainted
    if (validReadAddr) { // only if we are actually reading in this instruction
        cout << readAddr;
        if (TMS.find(readAddr) != TMS.end())
            taint = true;
    }

    taint_array[write_reg] = taint ? 2 : 0;

}

// POP analysis
// We look for the taint of the stack pointer address and assign it to the taint of the register
VOID popAnalysis(ADDRINT ip, ADDRINT sp) {
    bool taint = TMS.find(readAddr) != TMS.end();
    
    REG write_reg = writeRegMap[ip];
    taint_array[write_reg] = taint;
}


VOID printState(ADDRINT ip, REG flags, REG esp) {
    // cleanup code after everything
    // removes the 0th taint array element, which is the invalid register
    taint_array[0] = 0;

    // and print
    print_all(ip, flags, esp);
}

VOID saveReadAddr(ADDRINT addr) {
    readAddr = addr & 0xffffffff;
    validReadAddr = true;
}

VOID setReadInvalid() {
    validReadAddr = false;
}

VOID saveWriteAddr(ADDRINT addr) {
    writeAddr = addr & 0xffffffff;
    validWriteAddr = true;
}

VOID setWriteInvalid() {
    validWriteAddr = false;
}



////////////////////////////////////////////////////////////////////////////////////////////////////
//---------------------------------------INSTRUCTION ROUTINE---------------------------------------
////////////////////////////////////////////////////////////////////////////////////////////////////

VOID Instruction(INS ins, VOID *v){

    if(flag){    // open files
        // Mihailo's instrumentation setup
        RegValuesFile.open("/disk/logs/values.out");
        for (int i=0; i<TAINT_ARRAY_SIZE; i++)
            taint_array[i] = 0;

        flag=false;
    }
    
    /////////////////////////////////////////////
    // bookeeping 
    ////////////////////////////////////////////
    
    ADDRINT addr         = INS_Address(ins);
    disAssemblyMap[addr] = INS_Disassemble(ins);
    categoryMap[addr]    = CATEGORY_StringShort(INS_Category(ins));
    mnemonicMap[addr]    = INS_Mnemonic(ins);

    /////////////////////////////////////////////
    // Memory Instructions
    ////////////////////////////////////////////

    // saving the addresses before using
    if (INS_IsMemoryRead(ins))
        INS_InsertCall(ins, IPOINT_BEFORE, 
            (AFUNPTR) saveReadAddr,
            IARG_MEMORYREAD_EA,
            IARG_END);
    else
        INS_InsertCall(ins, IPOINT_BEFORE, 
            (AFUNPTR) setReadInvalid,
            IARG_END);

    if (INS_IsMemoryWrite(ins))
        INS_InsertCall(ins, IPOINT_BEFORE, 
            (AFUNPTR) saveWriteAddr,
            IARG_MEMORYWRITE_EA,
            IARG_END);
    else 
        INS_InsertCall(ins, IPOINT_BEFORE,
            (AFUNPTR) setWriteInvalid,
            IARG_END);


    // for allowing IPOINT_AFTER
    if (INS_HasFallThrough(ins)) { // FIXME

        if(INS_IsMemoryWrite(ins) && INS_IsMemoryRead(ins)) { //some instructions both read and write to mem.
            // i.e add qword ptr [rax+0x8], r14
            // for those ones, we need write or read (same) address. Also we should check if we are using reg or IMM value to call the function.

            // FIXME extract to a separate function
            // ADD,OR,AND,SUB
            // FIXME add other opcodes
            if (INS_Opcode(ins)==8 || INS_Opcode(ins)==460 || INS_Opcode(ins) ==23 || INS_Opcode(ins)==761) {

                // first we should check if we are using reg or IMM value to call the instruction
                bool validIndex, validBase;// store validity of base and index register
                REG baseR = INS_OperandMemoryBaseReg(ins, 0); 
                validIndex = REG_valid(baseR);
                REG indexR = INS_OperandMemoryIndexReg(ins, 0);
                validBase=REG_valid(indexR);
                UINT32 regNo=0;	

                if (validBase && validIndex) 
                    regNo = 2;
                else if( validBase || validIndex) 
                    regNo = 1;

                // checking if the source operand is an immediate or a register
                REG readR = REG_INVALID_; // which Reg is read!
                UINT32 maximr = INS_MaxNumRRegs(ins); // # of read reg.
                if (maximr > regNo) 
                    readR = INS_RegR(ins, maximr - 1);// eg. add qword ptr [rip+offset],rdi

                REG flagreg = REG_GFLAGS; // need OF flag

                // add the second operand to a map with this address
                ADDRINT addr = INS_Address(ins);
                secondOperandMap[addr] = (REG_valid(readR)) ? readR : REG_INVALID_;

                // if the second operand is a register
                INS_InsertCall(ins, IPOINT_AFTER,
                        (AFUNPTR) binaryRWAnalysis,
                        IARG_UINT32, ins,
                        IARG_INST_PTR,
                        //IARG_MEMORYREAD_EA,
                        IARG_REG_VALUE, flagreg,
                        IARG_END);	
            }
            
            // what we should do for "PUSH" 
            // push qword ptr [rip+0x3a3842]
            // TODO test me
            else if(INS_Opcode(ins) == 633) { 
                INS_InsertCall(ins, IPOINT_AFTER,
                        (AFUNPTR) pushRWAnalysis,
                        //IARG_MEMORYREAD_EA,
                        IARG_REG_VALUE, REG_ESP,
                        IARG_END);
            }
            else 
                std::cerr << "Undefined 'Both Read&Write Mem Inst'! Disassembling... 	" << INS_Disassemble(ins) << endl;
        }

        // TODO check if there is an op 
        //  Only memory write instruction
        else if (INS_IsMemoryWrite(ins)) {

            //MOV 
            if (INS_Opcode(ins) == 397){
                bool validIndex, validBase; // store validity of base and index register
                REG baseR = INS_OperandMemoryBaseReg(ins,0);
                validIndex = REG_valid(baseR);
                REG indexR = INS_OperandMemoryIndexReg(ins,0);
                validBase = REG_valid(indexR);
                UINT32 regNo = 0;	

                if (validBase && validIndex) 
                    regNo=2;
                else if (validBase || validIndex) 
                    regNo=1;

                REG readR = REG_INVALID_; //which Reg is read!
                UINT32 maximr = INS_MaxNumRRegs(ins); // # of read reg.
                if (maximr > regNo) 
                    readR = INS_RegR(ins, maximr - 1); // eg. mov qword ptr [rip+offset],rdi

                // add the register operand to a map with this address
                ADDRINT addr = INS_Address(ins);
                secondOperandMap[addr] = (REG_valid(readR)) ? readR : REG_INVALID_;

                // At this point I should get taint value of read register to feed to the analysis routine
                INS_InsertCall(ins, IPOINT_AFTER,
                        (AFUNPTR) movWAnalysis,
                        IARG_INST_PTR,
                        //IARG_MEMORYWRITE_EA,
                        IARG_END);	
            }	

            // pushing a register
            else if(INS_Opcode(ins) == 633){
                REG readR = REG_FullRegName(INS_RegR(ins, 0));
                ADDRINT addr = INS_Address(ins);

                secondOperandMap[addr] = (REG_valid(readR)) ? readR : REG_INVALID_;

                INS_InsertCall(ins,IPOINT_AFTER,
                        (AFUNPTR) pushWAnalysis, // for push funct. if reg tainted add
                        IARG_INST_PTR,
                        IARG_REG_VALUE, REG_ESP, 
                        IARG_END);	
            }	
            else std::cerr<<"Undefined 'Only Write Mem Inst'! disassembling..."<<INS_Disassemble(ins)<<endl;

        }

        // Result possibly saved to register, operands are registers and memory 
        // The taint can come from the registers or memory, and the operation can overflow introducting taint
        //else if (INS_IsMemoryRead(ins)) { 
        // FIXME possibly we need two codes, one that assumes we have a memory read and one that does not
        else { 
            // NOTE: REG baseR=INS_OperandMemoryBaseReg(ins,1);
            // check if should be 1 or 0
            

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

            // FIXME disregard base and index register
            const UINT32 max_r = INS_MaxNumRRegs(ins); 
            for (unsigned int i=0; i<max_r; i++) {
                REG read = REG_FullRegName(INS_RegR(ins, i));
                if (REG_is_gr(read)) // just the general purpose registers
                    readRegMap[addr].insert(it, read);
            }

            readRegMap[addr] = readList;

            INS_InsertCall(ins, IPOINT_AFTER, //this might be IPOINT_AFTER, we might need to check FLAGS after ins execution done 
                (AFUNPTR) taintAnalysis,
                IARG_INST_PTR,
                IARG_UINT32, ins,
                IARG_REG_VALUE, FLAGS_REG_INDEX,
                //IARG_MEMORYREAD_EA,
                IARG_END);
        }

        if (INS_HasFallThrough(ins))
            INS_InsertCall(ins, IPOINT_AFTER, //this might be IPOINT_AFTER, we might need to check FLAGS after ins execution done 
                (AFUNPTR) printState,
                IARG_INST_PTR,
                IARG_REG_VALUE, FLAGS_REG_INDEX,
                IARG_REG_VALUE, REG_ESP,
                IARG_END);
    }    
}


//////// Finish fun ////////////

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    //for(std::set<ADDRINT>::iterator it=TMS.begin();it!=TMS.end(); ++it) 
        //std::cout<<' '<<*it;
    //std::cout<<"END OF PINTOOL"<<endl;
}
/////////

INT32 Usage()
{
    cerr << "This tool track memory operations" << endl;
    return -1;
}

int main(int argc, char * argv[]){



    if (PIN_Init(argc, argv)) return Usage();

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;




    return 0;
}
