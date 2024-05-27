**FINDINGS**

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


**EXPLOIT SUMMARY**

1) Send crash payload
2) Send log_message exploit to create keylogger file
3) Send keylogger data using POST request
4) Send run keylogger exploit
