

// Created by sadullah
// Based on the inscount0.cpp file
// 12th bit is overflow bit.

#include <iostream>
#include <fstream>
#include "pin.H"
#include <bitset>
#include <string>
#include <iomanip>
#include <set>

#if defined(TARGET_MAC)
#define MALLOC "_malloc"
#define FREE "_free"
#else
#define MALLOC "malloc"
#define FREE "free"
#endif


ofstream OutFile2;// OPCODES, disassemble format  //op_disass_taint.out
ofstream OutFile3; // FLAGS  // flags_taint.out
ofstream OutFile4; // GENERAL PURPOSE REGISTER VALUES //gp_regval_taint.out
ofstream OutFile6;
ofstream OutFile7; // memory read instructions
ofstream OutFile8; // memory both write&read instructions
std::ofstream TraceFile;
std::ofstream TraceFile2;


bool flag=true;

std::set<ADDRINT> taintedAddr;



////////////////////////////////////////////////////////////////
// Analysis routine:This function is called before every instruction is executed
////////////////////////////////////////////////////////////////


VOID Arg1Before(CHAR * name, ADDRINT size)
{
	TraceFile << name << "(" << size << ")" << endl;
	std::cout<<"Arg1Before"<<endl;
}

VOID MallocAfter(ADDRINT ret)
{

	TraceFile << "  returns " << ret << endl;

	std::cout<<"MallocAfter"<<endl;

}


VOID Image(IMG img, VOID *v)
{
	// Instrument the malloc() and free() functions.  Print the input argument
	// of each malloc() or free(), and the return value of malloc().

	//
	//  Find the malloc() function.
	RTN mallocRtn = RTN_FindByName(img, MALLOC);
	if (RTN_Valid(mallocRtn))
	{
		RTN_Open(mallocRtn);
		//std::cout<<"MALLOC:"<<INS_Disassemble(img)<<endl;
		TraceFile2<<"IMAGE"<<endl;
		//std::cout<<"IMAGE"<<endl;


		//Mihailo: Check if the RDI is tainted and if that is the case EXCEPTION!!!!!!!!



		// Instrument malloc() to print the input argument value and the return value.
		RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before,
				IARG_ADDRINT, MALLOC,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);
		RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter,
				IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

		RTN_Close(mallocRtn);
	}

	// Find the free() function.
	RTN freeRtn = RTN_FindByName(img, FREE);
	if (RTN_Valid(freeRtn))
	{
		RTN_Open(freeRtn);
		// Instrument free() to print the input argument value.
		RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before,
				IARG_ADDRINT, FREE,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);
		RTN_Close(freeRtn);
	}


}
//////////////////////////////////////////////////////////////////////
// Instrumentation routine: for each instruction call this function
//////////////////////////////////////////////////////////////////////

VOID Instruction(INS ins, VOID *v)
{



	TraceFile2<<"INS:"<<INS_Disassemble(ins)<<endl;
	string regRead,regWrite;//keeps the name of written and read registers



	///////////////////////////////
	// TAINT ARRAY INITIZALITON
	//////////////////////////////

	if(flag){    // initialize taint array for just once

		//OutFile.setf(ios::showbase);//open file
		TraceFile.setf(ios::app | ios::out);
		TraceFile.open("outputfiles/mallocsado.out");

		TraceFile2.setf(ios::app | ios::out);
		TraceFile2.open("outputfiles/mallocsado2.out");


		OutFile2.setf(ios::app | ios::out);//open file
		OutFile2.open("outputfiles/op_disass_taint.out");	

		OutFile3.setf(ios::app | ios::out);//open file
		OutFile3.open("outputfiles/flags_taint.out");

		OutFile4.setf(ios::app | ios::out);//open file
		OutFile4.open("outputfiles/gp_regval_taint.out");	

		OutFile6.setf(ios::app | ios::out);//open file
		OutFile6.open("outputfiles/writeins.out");

		OutFile7.setf(ios::app | ios::out);//open file
		OutFile7.open("outputfiles/readins.out");

		OutFile8.setf(ios::app | ios::out);//open file
		OutFile8.open("outputfiles/writereadins.out");

		flag=false;
	}




	///////////////////////////////////////
	// OPCODES
	//////////////////////////////////////

	//std::cout<<INS_Disassemble(ins)<<endl;
	OutFile2<<"opcode:"<<INS_Opcode(ins)<<" opcodename:"<<INS_Mnemonic(ins)<<" ";
	OutFile2<<hex<<"ins_address:"<<INS_Address(ins)<<" ; " <<INS_Disassemble(ins)<<endl;//disassembling the instruction, check instruction address!!!!

	////////////////////////////////////////////
	// Memory Write Instructions
	////////////////////////////////////////////
	if(INS_IsMemoryWrite(ins)&INS_IsMemoryRead(ins)){

		OutFile8<<std::left<<std::setw(6)<<INS_Opcode(ins)<<" "<<std::setw(10)<<INS_Mnemonic(ins)<<"  " <<std::setw(32)<<INS_Disassemble(ins)<<std::setw(20)<<CATEGORY_StringShort(INS_Category(ins))<<endl;

	}
	else if(INS_IsMemoryWrite(ins)){
		OutFile6<<std::left<<std::setw(6)<<INS_Opcode(ins)<<" "<<std::setw(10)<<INS_Mnemonic(ins)<<"  " <<std::setw(32)<<INS_Disassemble(ins)<<endl;

		UINT32 maximr=INS_MaxNumRRegs(ins);

		OutFile6<<std::setw(32)<<"~ "<<" Dis:"<<INS_OperandMemoryDisplacement(ins,0)<<" Index:"<<INS_OperandMemoryIndexReg(ins,0)<<" scale:"<<INS_OperandMemoryScale(ins,0)<<" ctg:"<<CATEGORY_StringShort(INS_Category(ins))<<" "<<REG_StringShort(INS_OperandMemoryBaseReg(ins,0))<<":"<<ADDRINT(INS_OperandMemoryBaseReg(ins,0))<<" "<<REG_StringShort(INS_OperandMemoryIndexReg(ins,0))<<":"<<ADDRINT(INS_OperandMemoryIndexReg(ins,0))<<" RReg:"<<REG_StringShort(INS_RegR(ins,maximr-1))<<endl;


	}
	///////////////////////////////////////////
	// Memory Read Instructions
	//////////////////////////////////////////

	else if(INS_IsMemoryRead ( ins)){ 

		OutFile7<<std::left<<std::setw(6)<<INS_Opcode(ins)<<" "<<std::setw(10)<<INS_Mnemonic(ins)<<"  " <<std::setw(32)<<INS_Disassemble(ins)<<" memcnt:"<<INS_MemoryOperandCount(ins)<<endl;

		//if(INS_IsMov(ins))
		OutFile7<<std::setw(32)<<"Base:"<<INS_OperandMemoryBaseReg(ins,1)<<" Dis:"<<INS_OperandMemoryDisplacement(ins,1)<<" Index:"<<INS_OperandMemoryIndexReg(ins,1)<<" scale:"<<INS_OperandMemoryScale(ins,1)<<" ctg:"<<CATEGORY_StringShort(INS_Category(ins))<<" "<<REG_StringShort(INS_OperandMemoryBaseReg(ins,1))<<":"<<ADDRINT(INS_OperandMemoryBaseReg(ins,1))<<" "<<REG_StringShort(INS_OperandMemoryIndexReg(ins,1))<<":"<<ADDRINT(INS_OperandMemoryIndexReg(ins,1))<<" WReg:"<<REG_StringShort(INS_RegW(ins,0))<<endl;

	}


}
//KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
//    "o", "outputfile/icount.out", "specify output file name");

INT32 Usage()
{
	cerr << "This tool produces a trace of calls to malloc." << endl;
	cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}


// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
	// Write to a file since cout and cerr maybe closed by the application
	//  cerr<< "Count " << icount << endl;
	//    OutFile.close();
	OutFile2.close();
	OutFile3.close();
	OutFile4.close();
	OutFile6.close(); 
	OutFile7.close();
	OutFile8.close();

	TraceFile.close();
	TraceFile2.close();
}


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

int main(int argc, char * argv[])
{
	// Initialize pin
	PIN_InitSymbols();
	//PIN_InitSymbolsAlt():
	if (PIN_Init(argc, argv)) return Usage();

	INS_AddInstrumentFunction(Instruction, 0);
	// Register Image to be called to instrument functions.

	IMG_AddInstrumentFunction(Image, 0);
	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);
	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}



