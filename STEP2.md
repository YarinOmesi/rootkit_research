# Step 2
output of example ls with stace [here](./ls_strace.txt)

i am suspecting the relevant syscall is `getdents64` get directory entries.

i think about 

- changing file entry type to `DT_UNKNOWN`
- change file inode number (maybe cause missmatch with stat?)
- /home/yarin/code/rootkit_research/linux/Documentation/filesystems/seq_file.rst file iterator ??
- intercepting somehow the call to `getdents64` and filtering my entries
  - reading about linux traps
  - ptrace
    - https://stackoverflow.com/questions/18577956/how-to-use-ptrace-to-get-a-consistent-view-of-multiple-threads
    - https://security.stackexchange.com/questions/33528/force-all-user-processes-to-be-ptraced


trying to listen to new processes and attach to them by ptrace
then i could control syscall invocation and return values