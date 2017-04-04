#! /bin/bash

# Script runs the string compare pintool on a binary provided in the first parameter, 
# and saves the results to the file provided in the second parameter. The pintool dumps the memory
# every time it hits on a function set in pintools/strcmp_dump.cpp, which in our case is the compare
# function in the class string, from the standard library.

PINTOOL=pintools/obj-intel64/strcmp_dump.so

$PIN_ROOT/pin -t $PINTOOL -- $1 > $2
