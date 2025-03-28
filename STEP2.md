# Step 2
output of example ls with stace [here](./ls_strace.txt)

i am suspecting the relevant syscall is `getdents64` get directory entries.

flow of data

`<Magical Filesystem>` -> `getdents64` -> `readdir` -> `ls`

i know i cannot touch `ls` and `readdir`
so my option are:
1. changing the `fs` to be reflected in `getdents64`
2. intervening somehow in `getdents64`

ideas for option `1.`
- changing file entry type to `DT_UNKNOWN`
- change file inode number (maybe cause missmatch with stat?)
- /home/yarin/code/rootkit_research/linux/Documentation/filesystems/seq_file.rst file iterator ??

ideas for option `2.`
intercepting somehow the call to `getdents64` and filtering my entries

found this https://docs.kernel.org/core-api/entry.html

## Selecting Interception Method

#### signals
reading about linux traps
not that relevant because this is different than syscall

### ptrace
- https://stackoverflow.com/questions/18577956/how-to-use-ptrace-to-get-a-consistent-view-of-multiple-threads
- https://unix.stackexchange.com/questions/649368/interception-syscalls-and-make-change-in-their-arguments 
- https://security.stackexchange.com/questions/33528/force-all-user-processes-to-be-ptraced
- https://www.linuxjournal.com/article/6100
- https://stackoverflow.com/questions/12974110/simple-kernel-multithreading

### Tools 
systemtap

https://stackoverflow.com/questions/29840213/how-do-i-trace-a-system-call-in-linux

reading this lead me to `trace` directory and to `ftrace`/ `fprobe`

### `fprobe` / `ftrace`
https://docs.kernel.org/trace/fprobe.html
reference to `kprobes`

1. tried implementing module that register entry method of `syscall()` and `getdent64`, my entry log did not reached
2. tried `fprobe` on `kernel_clone` so i could to `ptrace` to every new process that didnot work because `ptrace` wrapper is in `libc` and i cannot use it in the kernel
    
### `kprobes`
`sudo cat /proc/kallsyms | grep getdents`
    
most interesting symbols

- `__event_enter__getdents64`
    - https://stackoverflow.com/questions/78566725/kprobe-on-getdents64-fails
- `__x64_sys_getdents64`
 TODO check that how to get return value 

https://stackoverflow.com/questions/78668467/cannot-read-syscall-arguments-from-a-kprobe-handler

### `kretprobes`
`https://www.kernel.org/doc/Documentation/kprobes.txt`:
There are currently two types of probes: kprobes, and kretprobes
(also called return probes).  A kprobe can be inserted on virtually
any instruction in the kernel.  A return probe fires when a specified
function returns.


>switching to use `kretprobe` in order to get the return value of the syscall.

## Implementation Notes
`getdents` returns only filename.

found `regs_set_return_value` to change return value.


### How I Am Hiding A File
for now hiding all files named `hideme`.

using `kretprobe` for callbacks when `getdent64` syscall enters and returns.

1. when syscall enters, i capture all its arguments (directory fd, buffer ptr, buffer size)
2. when syscall returns, i capture the return value (the length of entries in buffer bytes)
3. searching the result entries to hide at the provided buffer.
4. if entry found, copy the rest of the buffer over the found entry (so it will be overridden with the next entry)
5. change the return value to the new length to entries in buffer (substrate the entry size of entry to hide from the original size)



## General Notes
i have had the init log and cleanup log mixed up, found this online https://stackoverflow.com/questions/12861230/kernel-module-init-and-exit-functions-being-called-in-wrong-order


learn here that i can list all kernel symbols:

https://ebpfchirp.substack.com/p/tracepoints-kprobes-or-fprobes-which
