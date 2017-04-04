/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2016 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */

#include "pin.H"
#include <iostream>
#include <fstream>

using namespace std;

#define MEMORY_DUMP_SIZE 100000
#define TARGET_FUN "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareERKS4_"

    
/*
 * Analysis function. Using PIN_SafeCopy, which attempts to copy memory from address to address and safely stops if we
 * don't have access, dumps MEMORY_DUMP_SIZE bytes into standard output, which hopefully contain the URLs we need.
 */
VOID printFuncMem() {

    char text[MEMORY_DUMP_SIZE];
    PIN_SafeCopy(text, (void *) 0x400000, MEMORY_DUMP_SIZE);

    // For some reason, printing codes lower than 20 screws up the output, so replace them with '?'
    for (int i=0; i<MEMORY_DUMP_SIZE; i++)
        if (text[i] < 0x20)
            text[i] = '?';

    printf("%s\n", text);
}

/*
 * Instrumentation routine, searches the function with name in TARGET_FUN, and assuming that the program has already 
 * decrypted the URLs which are somewhere in memory, dumps MEMORY_DUMP_SIZE bytes into standard output.
 */
VOID Image(IMG img, VOID *v) {
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            RTN_Open(rtn);
            
            // if the function name is TARGET_FUN, dump memory
            if (RTN_Name(rtn).compare(TARGET_FUN) == 0)
                if (RTN_Valid(rtn))
                    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) printFuncMem, IARG_END);

            // to preserve space, release data associated with RTN after we have processed it
            RTN_Close(rtn);
        }
   
}

VOID Fini(INT32 code, VOID *v) {}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    // Initialize pin & symbol manager
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return Usage();

    // Register ImageLoad to be called to instrument instructions
    IMG_AddInstrumentFunction(Image, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
/* ===================================================================== */
    
