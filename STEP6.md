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


## Implementation Notes
1. Implemented Idea 1, Removed the line in `/proc/modules` that describe my module as a result `lsmod` does not show my module.

## Notes 
1. we still can see the loaded modules with `ls /sys/modules`