**FINDINGS**

Exploit in POST, writes the given data to the appointer file, data.txt in this case

The handle and next handle_client functions are called after the POST request is sent

The handle_client function makes a buffer and later puts the POST-PAYLOAD in that buffer

Later the handle_client function calls the parse_request function which reads the buffer and writes it to the data.txt file

Because we only wrote a small amount of data to the buffer, the rest of the buffer is filled null bytes and doesn't get overwritten,

but we also passed in the POST request a very large Content-Length, which causes the parse_request > build_200_response_append function to read the buffer fully and more.

Thus causing it to write the buffer but also all the data on the stack above the buffer to the data.txt file

This data contains the stack of the handle_client function and handle and all the data that was pushed on the stack

Now we can find the RET address back to the handle function, but in this case we used RAX since that points to the first instruction of handle.

Like in this stack:

    handle | handle_client

    |

    <===========================================>

    `<pushes>`<======================0x530========>

    |                    <===POST-PAYLOAD===>

    |

    |

    └> <...rbp,rbx,RAX,RET,rbp,r15,r14,r12,rbx> ---> view demo.txt

Like in scenario 2, we can use the same technique and execute a ROP chain to run the keylog binary

The problem due to ASLR is that all the addresses in this chain arn't static.

But since we now the address of the handle function of the current run,

we can calculate the offset to the original handle function which the ROP chain is based on.

We can then use that to calculate the offset to the ROP chain addresses.

Now our ROP chain is adjusted to the servers base address offset of ASLR and we can execute it to run the keylog binary.



**EXPLOIT SUMMARY**

1. POST request with a large Content-Length and small payload to write the stack to the data.txt file
2. Download the data.txt file and find the RET address back to the handle function
3. Calculate the offset to the original handle function and adjust the ROP chain to the servers base address offset
4. Adjust the ROP chain to the servers base address offset
5. Send the ROP chain to the server to execute the keylog binary
