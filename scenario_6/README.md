**FINDINGS**

1.  Fork process on server and brute force test possible values for the stack canary to find the stack cookie X Can't run shell code DEP or ROPChain due to ASLR (can't leak it too)

2.  Leak the stack canary from the stack and just use that X ServerData private

3.  Heap spray X DEP and heap is not executable

4.  ELF .dynamic section function interposition,

    Write our own functions to override existing functions, this allows our versions of the functions to be used instead of those in the standard libraries.

    Specify a shared library to be loaded before all others using the LD_PRELOAD environment variable

    After that when the program calls a function, the dynamic linker resolves it to our wrapper instead of the original function.

    So for example we can override the malloc function to run the keylog binary which is included in the shared library

    But how to get the shared library on the server and set the LD_PRELOAD environment variable?

    Again find a exploit in the program to write the shared library to the server and set the LD_PRELOAD environment variable



**EXPLOIT SUMMARY**

No exploit found due to time constraints
