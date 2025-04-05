# Step 6

## What `lsmod` does
1. openat + read `/proc/cmdline` ? 
2. openat + read `/proc/modules` provide list of loaded modules
3. for each module
    1. openat + read `/sys/module/<module_name>/refcnt`
    2. read from (openat `/sys/module/<module_name>` -> openat `coresize`) 
    3. openat + getdents `/sys/module/<module_name>/holders` to get module that reference it
    4. print module line to stdout


## Ideas
1. must hook `read` of `/proc/modules` to hide my module.

if `1.` not enough

2. hook `openat` and return not found on any files under : `/sys/module/yarin_module/*`