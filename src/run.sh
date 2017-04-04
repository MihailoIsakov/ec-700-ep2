#! /bin/bash

# Runs the pintool for dumping memory on a string compare on the specified binary, saves the output
# to the logfile, then finds the urls in the logfile.

BINARY=examples/bin/malware
LOGFILE=dump.out

./dump_mem.sh $BINARY $LOGFILE
echo `./find_urls.py $LOGFILE`
