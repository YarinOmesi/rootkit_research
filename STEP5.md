# Step 5

## What Regular UDP server does
1. `socket` 
2. `bind`
3. `recvfrom`
    1. the kind of content that will be in the buffer depends on socket type
        if the socket is udp only the payload, if raw also the buffer.



## Notes
1. Implement UDP server and client in cli application in c
    that send/recv string messagess
    1. strace of udp server


## Ideas
find the kernel code:
1. do sockets
2. pealing the packets 
