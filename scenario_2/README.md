**FINDINGS**

Use the same approach as in scenario_1 to exploit the server.

Because DES we can't run the shellcode directly, we need to use a ROP chain to replace this shellcode.

The ROP chain will execute the 'execve' system call to run the keylog binary.

This ROP chain sarts at the return address of log_message and goes up the stack.

A problem was the increment of rax to 59, which resulted in to many bytes in the buffer.

To fix this we just put 59 on the stack and load it into rax using a pop before the syscall.

Another problem was that the ./keylogger name was larger than rsi (64 bits), so we named it keylog.



**EXPLOIT SUMMARY**

1. Copy the 'keylogger' binary to 'server_data'
2. Send a GET request that overflow the buffer of log_message as in scenario_1 and put the first instruction of the ROP chain on the return address
3. Exploited
