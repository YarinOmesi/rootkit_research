# Step 4

## What `ps` do
1. open `fd` at `/proc`
2. call `getdents64` syscall
3. for each process
    1. call `newfstatat` on `/proc/pid`
    2. `openat` and `read` `/proc/pid/stat`
    3. `openat` and `read` `/proc/pid/status`
    4. `openat` and `read` `/proc/pid/environ`
    5. `openat` and `read` `/proc/pid/cmdline`


## Ideas
1. hide my process pid from first `getdents`. This did not work, `ps` outputed an error
    