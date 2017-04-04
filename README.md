# Jeez - a tool for extracting URL targets from web injection malware

Web injection malware typically stays dormant on a compromised machine, waits until the user visits a certain website (for example https://bankofamerica.com), and then tries to inject extra fields and siphon information from the web session. The malware does not store the URLs itself, but recieves them from a command & control server. The URLs and the malware code are typically kept encrypted until the last moment, meaning static analysis does not help us find the targeted sites. 

Jeez uses Intel Pin to create a dynamic trace of the program and attempt to extract the URLs the C&C is targeting. We assume that at a certain point in the execution of the binary, the malware will call a string comparison function. That means that the malware has previously extracted the URLs, which now reside in memory. We dump the memory at the time of the call, and run a simple script to extract the wanted URLs.

## Installing

The interesting stuff lies in the pintools/ directory. The proccount.cpp pintool is used to list out the functions that are called by the malware. From those functions, the user needs to find what exactly the strcmp, strncmp, or whichever string comparison function the malware uses is called. This name changes between compilers and platforms.
Once the user has the name, he needs to update the pintool strcmp_dump.cpp, add the new name, and run the makefile.
This requires setting the PIN_ROOT environment variable. 

Once you have the pintools compiled, run the proccount pintool on the malware, and find the name of the string compare function. Then insert the name of the function in the strcmp_dump.spp pintool, in the TARGET_FUN definition, and compile it. Next, update the PINTOOL variable in the dump_mem.sh script to point to the pintool binary. Finally, update the BINARY variable in the run.sh script with the path to your malware, and run the script.

**The script should now output the list of URLs the malware receives once it connects to the C&C server.**

## Malware 

We targeted the Citadel and Zeus malware. We cannot provide the binary nor the command and control server, for that
you will have to look yourself. The malware runs on Windows, and the C&C on Linux, using the LAMP stack.

## Built With

* [Intel Pin](https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool) - A dynamic
  Binary Instrumentation Tool

## Authors

* **Sarah Scheffler** 
* **Mihailo Isakov** - [MihailoIsakov](https://github.com/MihailoIsakov)


## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

