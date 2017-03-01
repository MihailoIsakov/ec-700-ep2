

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
#include <string.h>

#if defined(TARGET_MAC)
#define MALLOC "_malloc"
#define FREE "_free"
#define MEMCPY "_wmemcpy"
#else
#define MALLOC "malloc"
#define FREE "free"
#define MEMCPY "__libc_memalign"
#endif


std::ofstream TraceFile;
std::ofstream TraceFile2;
std::ofstream TraceFile3;

bool flag=true;

std::set<ADDRINT> taintedAddr;



////////////////////////////////////////////////////////////////
// Analysis routine:This function is called before every instruction is executed
////////////////////////////////////////////////////////////////


VOID Arg1Before(CHAR * name, ADDRINT size)
{
	TraceFile << name << "(" << size << ")" << endl;
	//	std::cout<<"Arg1MallocBefore"<<endl;
}

VOID MallocAfter(ADDRINT ret)
{

	TraceFile << "  returns " << ret << endl;

	//	std::cout<<"MallocAfter"<<endl;

}

VOID Arg1Memcpy(CHAR * name, ADDRINT size,ADDRINT arg1,ADDRINT arg2)
{
	TraceFile << name << "(" << size << ")" << "(" << arg1 << ")" <<"(" << arg2 << ")" <<endl;
	std::cout<<"Arg1MemcpyBefore"<<endl;
}

VOID Routine  (RTN rtn,VOID *v){

	TraceFile3<<RTN_Name(rtn)<<endl;


}

VOID Image(IMG img, VOID *v)
{
	// Instrument the malloc() and free() functions.  Print the input argument
	// of each malloc() or free(), and the return value of malloc().

	std::cout<< IMG_Name(img)<<endl;	//
	//  Find the malloc() function.
	RTN mallocRtn = RTN_FindByName(img, MALLOC);
	if (RTN_Valid(mallocRtn))
	{
		RTN_Open(mallocRtn);
		//std::cout<<"MALLOC:"<<INS_Disassemble(img)<<endl;
		//		TraceFile2<<"IMAGE"<<endl;
		//Mihailo: Check if the RDI is tainted and if that is the case EXCEPTION!!!!!!!
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

	// Find the memcpy() function
	RTN memcpyRtn=RTN_FindByName(img,MEMCPY);
	if(RTN_Valid(memcpyRtn)){

		RTN_Open(memcpyRtn);
		RTN_InsertCall(memcpyRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Memcpy,
				IARG_ADDRINT, MEMCPY,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,	IARG_FUNCARG_ENTRYPOINT_VALUE, 1,


				IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		RTN_Close(memcpyRtn);
	}


}


//////////////////////////////////////////////////////////////////////
// Instrumentation routine: for each instruction call this function
//////////////////////////////////////////////////////////////////////

VOID Instruction(INS ins, VOID *v)
{
	TraceFile2<<"INS:"<<INS_Disassemble(ins)<<endl;

	if(flag){    // initialize taint array for just once

		//OutFile.setf(ios::showbase);//open file
		TraceFile.setf(ios::app | ios::out);
		TraceFile.open("outputfiles/mallocsado.out");

		TraceFile2.setf(ios::app | ios::out);
		TraceFile2.open("outputfiles/mallocsado2.out");
		TraceFile3.setf(ios::app | ios::out);
		TraceFile3.open("outputfiles/mallocsado3.out");


		flag=false;
	}


}

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
	TraceFile.close();
	TraceFile2.close();
	TraceFile3.close();
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

	RTN_AddInstrumentFunction(Routine, 0);	
	IMG_AddInstrumentFunction(Image, 0);
	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);
	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}


