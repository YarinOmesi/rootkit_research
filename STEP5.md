# Step 5

https://docs.kernel.org/networking/skbuff.html


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
2. Searching In Linux Repo
    1. In Documentation directory
        1. Just open files that seems interesting 
        2. One of the files references `net/` directory in the repo
    2. In Source Directory
        1. found `netfilter` in `net/ipv4`.
        2. explored `arp_tables.c` and `ip_tables.c` file
            1. contains some kind of packet matching
            2. `xt_tables` ? after search online, got to this https://medium.com/@dipakkrdas/netfilter-and-iptables-f8a946bb83af



## Ideas
find the kernel code:
1. do sockets
2. pealing the packets 
