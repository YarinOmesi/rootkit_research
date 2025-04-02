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
2. make `newfstatat` return that the directory is not exists ? or cant be opned
3. make `openat` return that the directory is not exists ? or cant be opned


## Implementation Notes
Idea 2 seems to work, `ps` check file status before opening descriptor

so what i did is to make file status as not exists by hooking the used syscall `newfstatat` and returning `-1` when the `/proc/myprocpid` is queried.

the process is no longer visible when using `ps -a` and the server is fully functioning and i was abled to kill it.