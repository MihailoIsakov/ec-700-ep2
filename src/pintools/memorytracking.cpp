#include <iostream>
#include <fstream>
#include "pin.H"
//#include "redblacktree.h"
#include <bitset>
#include <iomanip>
//using namepace std;
#include<set>

//global variables

//RBtree tAT;//tainted address tree

ofstream OutFile6; // memory write instructions
ofstream OutFile7; // memory read instructions
bool flag=true;
UINT32 taintofReg;// used to set register taint for read addressing operations
std::set<ADDRINT> TMS;//tainted memory set



int get_bit(int value, int n) {
    // returns nonzero value if the nth bit is set
    // input n is zero-indexed
    return (int) (value & (1 << n));
}


/////////////////////////////////////////////////////////////////////////////////
// -----------------------------------------ANALYSIS ROUTINE--------------------
///////////////////////////////////////////////////////////////////////////////////



//// BOTH WRITE AND READ

VOID taint_MemRW1(ADDRINT EA,ADDRINT flagreg){
//reading from reg.

std::set<ADDRINT>::iterator it=TMS.find(EA);

	if(get_bit(flagreg,11) || taintofReg){
		TMS.insert(EA);// EA is not included =>
	} 

}

VOID taint_MemRW2(ADDRINT EA,ADDRINT flagreg){
//using IMM no reading from reg.
//bool isIncluded=TMS.search(EA);
//std::set<ADDRINT>::iterator it=TMS.find(EA);

	if(get_bit(flagreg,11)){
		TMS.insert(EA);
	} 

}

VOID taint_MemRW3(ADDRINT EA,ADDRINT sp){
//push qword ptr[rsp+0x58]

ADDRINT nextspaddr=sp-8;
std::set<ADDRINT>::iterator it=TMS.find(EA);
// if readed address(EA) is tainted, sp should set and vice versa.
if(it!=TMS.end())TMS.insert(nextspaddr);
else TMS.erase(nextspaddr);

}
//// ONLY MEMORY WRITE
VOID taint_MemW1(ADDRINT EA){ // write the value stored in a register to memory

//bool isIncluded=TMS.search(EA);// return true if address inside tree vice versa

	if(taintofReg ) // if reg contains tainted val
	TMS.insert(EA);

	else  // if reg is not tainted, remove it.
	TMS.erase(EA);
	
	//else std::cerr<<"UNKNOWN PATTERN-> function taintmemoryW"<<endl;
}

VOID taint_MemW2(ADDRINT EA){ // write IMM value to memory

 TMS.erase(EA);
	
}

VOID taint_MemW3(ADDRINT sp){ // PUSH: not sure about -8, should check it again.
ADDRINT nextspaddr=sp-8;
//bool isIncluded=TMS.search(nextspaddr);

// if pushed register is tainted; insert addr into set
if(taintofReg) TMS.insert(nextspaddr);
// If pushed register is not tainted, remove that address from RBT.
else  TMS.erase(nextspaddr);
}

////// ONLY MEMORY READ

// ------ MOV,MOVSX,MOVZX,ADD,SUB---------- //
VOID taint_MemR_MOV(ADDRINT EA, ADDRINT eflag){//effective addr,FLAG reg; update taint 
//mov rax,qword ptr [ rip+ 0x221d26 ]
//add r9, qword ptr[r8+0x8];  r9+addrval can also return tainted val,check flag


std::set<ADDRINT>::iterator it=TMS.find(EA);
//bool isIncluded=TMS.search(EA); //return true if address is tainted.

if(it!=TMS.end()|| get_bit(eflag,11)) taintofReg=1; // if address tainted or summation of them is overflow, register will contain tainted value
else taintofReg=0;  // vice versa.

}


VOID taint_MemR_POP(ADDRINT sp){
std::set<ADDRINT>::iterator it=TMS.find(sp);


if(it!=TMS.end()) taintofReg=1; // if sp address is tainted, reg should be set as tainted.
else  taintofReg=0;

}


////////////////////////////////////////////////////////////////////////////////////////////////////
//---------------------------------------INSTRUCTION ROUTINE---------------------------------------
////////////////////////////////////////////////////////////////////////////////////////////////////

VOID Instruction(INS ins, VOID *v){

if(flag){    // open files

	OutFile6.setf(ios::app | ios::out);//open file
        OutFile6.open("outputfiles/memtrack1.out");

	OutFile7.setf(ios::app | ios::out);//open file
        OutFile7.open("outputfiles/memtrack2.out");
	flag=false;
	}

/////////////////////////////////////////////
// Memory Instructions
////////////////////////////////////////////

if(INS_IsMemoryWrite(ins)&&INS_IsMemoryRead ( ins)){//some instructions both read and write to mem.
// i.e add qword ptr [rax+0x8], r14
// for those ones, we need write or read (same) address. Also we should check if we are using reg or IMM value to call the function.

	if(INS_Opcode(ins)==8 || INS_Opcode(ins)==460 || INS_Opcode(ins) ==23 || INS_Opcode(ins)==761){
	// ADD,OR,AND,SUB

	//first we should check if we are using reg or IMM value to call the function
	REG readR=REG_INVALID_;//which Reg is read!
	UINT32 maximr=INS_MaxNumRRegs(ins);// # of read reg.
	REG baseR=INS_OperandMemoryBaseReg(ins,0);
	REG indexR=INS_OperandMemoryIndexReg(ins,0);
	bool validIndex,validBase;// store validity of base and index register
	validIndex=REG_valid(baseR);
	validBase=REG_valid(indexR);
	UINT32 regNo=0;	
	
		if(validBase && validIndex) regNo=2;
		else if(validBase||validIndex) regNo=1;
	
		if(maximr>regNo) readR=INS_RegR(ins,maximr-1);// eg. add qword ptr [rip+offset],rdi
			
		REG flagreg=REG_GFLAGS;// need OF flag
	
		if(REG_valid(readR)){
		// At this point I should get taint value of read register to feed to the analysis routine
		
	      //*****taintofReg= Mihailo should provide me...
	
		INS_InsertCall(ins,IPOINT_BEFORE,
		   	   	(AFUNPTR)taint_MemRW1,
		      		IARG_MEMORYREAD_EA,
		      	//	IARG_UINT32,taintofReg,//taintofReg global:taint value of read register
				IARG_REG_VALUE,flagreg,
		      		IARG_END);	
		}

		else  { //e.g mov qword ptr [rip+0x20ce05],0x0 
		// IMM will be written to memory, clear taint of that address if it is set.	
   		INS_InsertCall(ins,IPOINT_BEFORE,
                       (AFUNPTR)taint_MemRW2,
                       IARG_MEMORYREAD_EA,
		       IARG_REG_VALUE,flagreg,
                       IARG_END);
 
		}
	//	else std:cerr<<"SADO"<<endl;

	}

	else if(INS_Opcode(ins)==633){ // what we should do for "PUSH" //push qword ptr [rip+0x3a3842], push reg

	//std::cerr<<"PUSH not implemented yet"<<endl;
		INS_InsertCall(ins,IPOINT_BEFORE,
                       (AFUNPTR)taint_MemRW3,
                       IARG_MEMORYREAD_EA,
		       IARG_REG_VALUE,REG_ESP,
                       IARG_END);
 

	
	}
	else std::cerr<<"Undefined 'Both Read&Write Mem Inst'!"<<"disassembling...	"<<INS_Disassemble(ins)<<endl;

}

//  Only memory write instruction
else if(INS_IsMemoryWrite(ins)){

OutFile6<<std::left<<std::setw(6)<<INS_Opcode(ins)<<" "<<std::setw(10)<<INS_Mnemonic(ins)<<"  " <<std::setw(32)<<INS_Disassemble(ins)<<endl;
	
	if(INS_Opcode(ins)==397){
	//MOV 
	REG readR=REG_INVALID_;//which Reg is read!
	UINT32 maximr=INS_MaxNumRRegs(ins);// # of read reg.
	REG baseR=INS_OperandMemoryBaseReg(ins,0);
	REG indexR=INS_OperandMemoryIndexReg(ins,0);
	bool validIndex,validBase;// store validity of base and index register
	validIndex=REG_valid(baseR);
	validBase=REG_valid(indexR);
	UINT32 regNo=0;	
	
		if(validBase && validIndex) regNo=2;
		else if(validBase||validIndex) regNo=1;
	
		if(maximr>regNo) readR=INS_RegR(ins,maximr-1);// eg. mov qword ptr [rip+offset],rdi
		//else readR=INS_RegR(ins,maximr);// this should return INVALID

		if(REG_valid(readR)){
		// At this point I should get taint value of read register to feed to the analysis routine
		//taintofReg= Mihailo should provide me...	
		INS_InsertCall(ins,IPOINT_BEFORE,
		   	   	(AFUNPTR)taint_MemW1,
		      		IARG_MEMORYWRITE_EA,
		      	//	IARG_UINT32,taintofReg,//taintofReg global, no need pass as argument.
		      		IARG_END);	
		}

		else{ //e.g mov qword ptr [rip+0x20ce05],0x0 
		// IMM will be written to memory, clear taint of that address if it is set.	
   		INS_InsertCall(ins,IPOINT_BEFORE,
                       (AFUNPTR)taint_MemW2,
                       IARG_MEMORYWRITE_EA,
                       IARG_END);
 
		}
	}	

	else if(INS_Opcode(ins)==633){
	// Mihailo should provide me the taint value of pushed register
		//taintofReg= ....
	//std::cerr<<"PUSH instruction is not implemented yet."<<endl;
		INS_InsertCall(ins,IPOINT_BEFORE,
		   	   	(AFUNPTR)taint_MemW3,// for push funct. if reg tainted add
		      		IARG_REG_VALUE,REG_ESP,// stack pointer(-8) will be inserted into RBT.
		      	   	IARG_END);	
			}	
	else std::cerr<<"Undefined 'Only Write Mem Inst'! disassembling..."<<INS_Disassemble(ins)<<endl;

}
else if(INS_IsMemoryRead ( ins)){ //// Memory Read Instructions


	if(INS_Opcode(ins)==397 || INS_Opcode(ins)==433 || INS_Opcode(ins) || INS_Opcode(ins)==761 || INS_Opcode(ins)==8 || INS_Opcode(ins)==1483){
	// MOV,MOVSXD,MOVZX,SUB,ADD,XOR

	/*REG baseR=INS_OperandMemoryBaseReg(ins,1);
	REG indexR=INS_OperandMemoryIndexReg(ins,1);
	ADDRINT displacement=INS_OperandMemoryDisplacement(ins,1);
	UINT32 scale=INS_OperandMemoryScale(ins,1);*/

	
	// Effective address=Displacement+BaseReg+IndexReg*Scale

	INS_InsertCall(ins, IPOINT_BEFORE,
                      (AFUNPTR)taint_MemR_MOV,
                      IARG_MEMORYREAD_EA,//effective read address
		      IARG_REG_VALUE,REG_GFLAGS,
		      IARG_END);	

	//REG writeR=INS_RegW(ins,0);//written register, should be updated by Mihailo
	//MIHAILO should update taint status of writeR,written register, by assigning thetaintofReg variable.
	

	}
	else if(INS_Opcode(ins)==580){
	//std::cerr<<"POP instruction is not implemented yet."<<endl;
	
	//Reg temp=INS_RegW(ins,0);// one reg will be written by popped value
		INS_InsertCall(ins, IPOINT_BEFORE,
                      (AFUNPTR)taint_MemR_POP,
		      IARG_REG_VALUE,REG_ESP,
		      IARG_END);	
	// Mihailo should update the taint status of written reg after insertcall

	}
	else
	std::cerr<<"Undefined 'Only Read Mem Inst'! disassembling..."<<INS_Disassemble(ins)<<endl;

	OutFile7<<std::left<<std::setw(6)<<INS_Opcode(ins)<<" "<<std::setw(10)<<INS_Mnemonic(ins)<<"  " <<std::setw(32)<<INS_Disassemble(ins)<<endl;

	}

}


//////// Finish fun ////////////

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    OutFile6.close(); 
    OutFile7.close();
	for(std::set<ADDRINT>::iterator it=TMS.begin();it!=TMS.end();++it) std::cout<<' '<<*it;
	std::cout<<"END OF PINTOOL"<<endl;
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
