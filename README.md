In order to make this, you have to:
* go to src with `cd src`
* set the PIN_ROOT to the Config folder, so type in a terminal:  
`export PIN_ROOT=/path/to/pin_directory`
* make the file `code.cpp` with:  
`make obj-intel64 code.so`  
Don't ask me why we just provide `code.so`, instead of `code.cpp`, I don't wanna look into the makefiles.

To run pin on some command, do:
`./runpin pintools/obj-intel64/some_pintool.se some_command`

