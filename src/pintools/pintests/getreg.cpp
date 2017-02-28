

// Created by sadullah
// Based on the inscount0.cpp file
// 12th bit is overflow bit.

#include <iostream>
#include <fstream>
#include "pin.H"
#include <bitset>
#include <string>

ofstream OutFile; // regdetails  //icount.out
ofstream OutFile3; // FLAGS  // flags_taint.out
ofstream OutFile4; // GENERAL PURPOSE REGISTER VALUES //gp_regval_taint.out
ofstream OutFile5; // regdetails  //regdetails.out
ofstream RegValuesFile; 
ofstream RegNamesFile; 
// The running count of instructions is kept here
// make it static to help the compiler optimize docount
static UINT64 icount = 0;

int taintarr [16];// Array that stores taints for each register
// Registers-> R15,R14,R13,R12,R11,R10,R9,R8,RSP,RDI,RSI,RBP,RDX,RCX,RBX,RAX
// R15=taintarr[15],......., RAX=taintarr[0]	

bool flag=true;



////////////////////////////////////////////////////////////////
// Analysis routine:This function is called before every instruction is executed
////////////////////////////////////////////////////////////////

//VOID printRegs(ADDRINT reg_flags,ADDRINT r8) { 

    //icount++;
    //// std::cerr<<hex<<"flags"<<<reg_al<<" icount:"<<icount<<endl;
    //OutFile3 <<icount<<")"<<" flags:" << bitset<12>(reg_flags) <<endl; 
    //OutFile4<<" R8:" << bitset<12>(r8) << endl;
//}

VOID printReg(VOID * ip, ADDRINT r) { 
    // std::cerr<<hex<<"flags"<<<reg_al<<" icount:"<<icount<<endl;
    RegValuesFile << ip << " = " << r << endl;
}

VOID Instruction(INS ins, VOID *v)
{


    //local arguments
    //const UINT32 max_r=INS_MaxNumRRegs(ins);//number of readed registers in the instruction
    const UINT32 max_w=INS_MaxNumWRegs(ins);//number of written registers in the instruction
    //string regRead,regWrite;//keeps the name of written and read registers


    if(flag){    // initialize taint array for just once
        for(int i=0;i<16;i++){
            taintarr[i]=0;
        }	

        OutFile.setf(ios::showbase);//open file

        OutFile3.setf(ios::app | ios::out);//open file
        OutFile3.open("logs/flags_taint.out");

        OutFile4.setf(ios::app | ios::out);//open file
        OutFile4.open("logs/gp_regval_taint.out");	

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
                IARG_INST_PTR,
                IARG_REG_VALUE, INS_RegW(ins, 0),
                IARG_END);
    }
}

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
        "o", "outputfile/icount.out", "specify output file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    // Write to a file since cout and cerr maybe closed by the application
    OutFile.setf(ios::showbase);
    OutFile<< "Count " << icount << endl;
    OutFile3.setf(ios::showbase);
    OutFile4.setf(ios::showbase);
    OutFile5.setf(ios::showbase);

    RegValuesFile.setf(ios::showbase);
    RegNamesFile.setf(ios::showbase);

    cerr<< "Count " << icount << endl;
    OutFile.close();
    OutFile3.close();
    OutFile4.close();
    OutFile5.close();

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

    //OutFile.open(KnobOutputFile.Value().c_str());

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}


// Functions that might be useful in the future

// REG_is_gr-> true if reg is a FULL WIDTH general purpose register
//http://www.cs.virginia.edu/kim/publicity/pin/docs/39599/Pin/html/group__REG__CPU__GENERIC.html#g120a492f7568ec264080f5e3376f9d60


//const REG reg= INS_RegR(ins,i); get the ith read register of the instruction

