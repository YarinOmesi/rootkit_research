# Step 2
output of example ls with stace [here](./ls_strace.txt)

i am suspecting the relevant syscall is `getdents64` get directory entries.

i think about 

- changing file entry type to `DT_UNKNOWN`
- change file inode number (maybe cause missmatch with stat?)
- /home/yarin/code/rootkit_research/linux/Documentation/filesystems/seq_file.rst file iterator ??