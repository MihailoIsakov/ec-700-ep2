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

#define TARGET_FUN "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareERKS4_"

char *url = "asdfqwertyuip                                                                                                                                                      ";

/*
 * Analysis routines
 */
    
VOID printFuncMem(REG edx) {
    //cout << "edx: " << edx << endl;
    char *text = (char*) malloc(sizeof(char) * 100);
    PIN_SafeCopy(text, (void *) edx, 100);
    cout << "edx: " << std::hex << edx << "; text: " <<  text << ";" << endl;
}

/*
 * Instrumentation routines
 */
VOID Image(IMG img, VOID *v) {


    UINT32 count = 0;
    
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    { 
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            // Prepare for processing of RTN, an  RTN is not broken up into BBLs,
            // it is merely a sequence of INSs 
            RTN_Open(rtn);
            
            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
            {
                count++;
            }

            if (RTN_Name(rtn).compare(TARGET_FUN) == 0)
                if (RTN_Valid(rtn)) {
                    RTN_InsertCall(rtn, 
                            IPOINT_BEFORE, (AFUNPTR) printFuncMem, 
                            IARG_REG_VALUE, REG_RDX, 
                            IARG_END);
                    //cout << "ayy caramba" << endl;
                }

            // to preserve space, release data associated with RTN after we have processed it
            RTN_Close(rtn);
        }
    }
    fprintf(stderr, "Image %s has  %d instructions\n", IMG_Name(img).c_str(), count);
}

VOID Fini(INT32 code, VOID *v)
{
    cout << url << endl;

}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    //cerr << "This is the invocation pintool" << endl;
    //cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
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

    // Write to a file since cout and cerr maybe closed by the application
    //OutFile.open(KnobOutputFile.Value().c_str());
    //OutFile.setf(ios::showbase);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
/* ===================================================================== */
    
