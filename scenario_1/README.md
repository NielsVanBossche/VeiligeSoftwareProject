
**Copied solution from the github of Alicia Andries and Ruben Mechelinck for the base struct****ure of this and further scenarios**

**FINDINGS**

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


**EXPLOIT SUMMARY**

1. Copy the 'keylogger' binary to 'server_data'
2. Send a GET request that overflows the buffer
3. The return address of log_message is overwritten with the address of the shell code
4. The shell code is executed to run the keylogger binary
5. Exploited
