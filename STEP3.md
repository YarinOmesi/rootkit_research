# Step 3
1. open http server with `python -m http.server 9090`
2. find server port with `netstat -tlnp`, found that [here](https://superuser.com/questions/529830/get-a-list-of-open-ports-in-linux).
3. use `strace` to figure out how `netstat` works. [example_output](./netstat_trace.txt)

what netstat do:
1. call `getdents64` on `/proc` to get all process (not only exists processes)
2. iterate all entries checking if `/proc/<PID>/fd` exists / not empty
3. open `fd` - points to directory with process information
4. call `getdents64` on opened `/proc/<PID>/fd`
5. iterate to find open `/proc/<PID>/fd/<FD>`
6. on open `fd` reading the content of link with `readlink`
7. if `fd` pointing to `socket` 
    1. get `cmeline` once
    2. for every `fd` that point to socket open and read from `/proc/<PID>/attr/current` ???? 
8. at the end reads from `/proc/net/tcp`



## Notes

### Different Port At `/proc/<PID>/fd/<FD>` then actual

1. at my python server process
   `readlink("/proc/5789/fd/3", "socket:[45944]", 29) = 14`

   but not `9090`

2. may be `45944` is the number of the socket. 
3. (2.) is right!
   
   from https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html docs
   
   For example, `socket:[2248868]` will be a socket and its
   inode is `2248868`.

   For sockets, that inode can be used to
   find more information in one of the files under `/proc/net/`.
4. can find information here `/proc/net/tcp` by socket inode
5. port is in `/proc/net/tcp` file at hex

   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   1: 00000000:2382 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 45944 1 0000000000000000 100 0 0 10 0

   my server is bound to `0.0.0.0:9090` and `local_address` is `00000000:2382`, 9090 = 0x2382


## Missing Directory Path 
1. need to find a way to get directory path from fd
2. https://stackoverflow.com/questions/33986081/resolving-file-descriptor-to-file-name-file-path
3. https://stackoverflow.com/questions/32265125/when-to-use-fcheck-or-fcheck-files-and-for-what
4. https://stackoverflow.com/questions/17885676/in-linux-how-can-i-get-the-filename-from-the-struct-file-structure-while-ste
5. found `files_lookup_fd_raw()` in `fdtable.h`
6. get `struct file` from ^ and get its path with `dentry_path_raw()`
7. there is a problem, because `/proc` is virtual fs so paths are `/<pid>/` instead of `/proc/<pid>/`
8. https://harryskon.wordpress.com/2015/03/31/vfs-proc-and-root-filesystems/
9. `file->f_path.mnt->mnt_sb` has reference to the superblock and `s_id` has its name. check it for `proc`
10. solved



## Implementation Notes
Idea
if `fd` of entry points to `/proc/<pidtohide>/fd/<fd with socket>` filter the entry.

1. get the directory from `fd`
2. if it is in `/proc/<pidtohide>/fd/`
   1.  for each `fd` do `readlink` to check if it is a socket - if it is filter the entry
         cannot do readlink in kernel
