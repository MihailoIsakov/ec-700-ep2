

// Created by sadullah
// Based on the inscount0.cpp file
// 12th bit is overflow bit.

#include <iostream>
#include <fstream>
#include "pin.H"
#include <bitset>

ofstream OutFile; // regdetails  //icount.out
ofstream OutFile2;// OPCODES, disassemble format  //op_disass_taint.out
ofstream OutFile3; // FLAGS  // flags_taint.out
ofstream OutFile4; // GENERAL PURPOSE REGISTER VALUES //gp_regval_taint.out
ofstream OutFile5; // regdetails  //regdetails.out
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

VOID printRegs(ADDRINT reg_flags,ADDRINT r8) { 

    icount++;
    // std::cerr<<hex<<"flags"<<<reg_al<<" icount:"<<icount<<endl;
    OutFile3 <<icount<<")"<<" flags:" << bitset<12>(reg_flags) <<endl; 
    OutFile4<<" R8:" << bitset<12>(r8) << endl;
}



//////////////////////////////////////////////////////////////////////
// Instrumentation routine: for each instruction call this function
//////////////////////////////////////////////////////////////////////

VOID Instruction(INS ins, VOID *v)
{


    //local arguments
    const UINT32 max_r=INS_MaxNumRRegs(ins);//number of readed registers in the instruction
    const UINT32 max_w=INS_MaxNumWRegs(ins);//number of written registers in the instruction
    string regRead,regWrite;//keeps the name of written and read registers



    ///////////////////////////////
    // TAINT ARRAY INITIZALITON
    //////////////////////////////

    if(flag){    // initialize taint array for just once

        for(int i=0;i<16;i++){

            taintarr[i]=0;

        }	

        OutFile.setf(ios::showbase);//open file

        OutFile2.setf(ios::app | ios::out);//open file
        OutFile2.open("logs/op_disass_taint.out");	

        OutFile3.setf(ios::app | ios::out);//open file
        OutFile3.open("logs/flags_taint.out");

        OutFile4.setf(ios::app | ios::out);//open file
        OutFile4.open("logs/gp_regval_taint.out");	

        OutFile5.setf(ios::app | ios::out);//open file
        OutFile5.open("logs/regdetails.out");
        flag=false;
    }


    /////////////////////////////////////
    // REGISTER VALUES
    ////////////////////////////////////

    bool isReadorWrite=false;//check if any of the register is read or written.

    for(UINT32 i=0;i<max_r;i++){    //to print the read registers


        regRead=REG_StringShort(INS_RegR(ins,i));	

        OutFile5<<"Regread:"<<regRead<<" , ";
        isReadorWrite=true;
    }


    for(UINT32 i=0;i<max_w;i++){    //to print the write registers

        regWrite=REG_StringShort(INS_RegW(ins,i));
        OutFile5<<"Regwrite:"<<regWrite<<" , " ;
        isReadorWrite=true;
    }
    if(!isReadorWrite) OutFile5<<"No Reg Read or Write";

    OutFile5<<endl;


    ///////////////////////////////////////
    // OPCODES
    //////////////////////////////////////


    OutFile2<<"opcode:"<<INS_Opcode(ins)<<" opcodename:"<<INS_Mnemonic(ins)<<" ";
    OutFile2<<hex<<"ins_address:"<<INS_Address(ins)<<" ; " <<INS_Disassemble(ins)<<endl;//disassembling the instruction, check instruction address!!!!

    //OutFile <<" flags:" << bitset<12>(REG_GFLAGS) << " R8:" << bitset<12>(REG_R8) << endl; this does not give proper results, no idea why


    INS_InsertCall(ins, IPOINT_BEFORE, //this might be IPOINT_AFTER, we might need to check FLAGS after ins execution done 
            (AFUNPTR)printRegs,
            IARG_REG_VALUE,REG_GFLAGS,
            IARG_REG_VALUE,REG_R8,
            IARG_END);
}

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
        "o", "outputfile/icount.out", "specify output file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    // Write to a file since cout and cerr maybe closed by the application
    OutFile.setf(ios::showbase);
    OutFile<< "Count " << icount << endl;
    OutFile2.setf(ios::showbase);
    OutFile3.setf(ios::showbase);
    OutFile4.setf(ios::showbase);
    OutFile5.setf(ios::showbase);

    cerr<< "Count " << icount << endl;
    OutFile.close();
    OutFile2.close();
    OutFile3.close();
    OutFile4.close();
    OutFile5.close();
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

