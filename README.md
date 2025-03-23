# rootkit_research

## Step 1

### How To Write A Module
- In Linux Repo, At linux/inlude/linux/module.h:80, code the describe initializing a module.
  - `module_init(fn)` `module_exit(fn)`
- After Looking at https://www.kernel.org/doc/html/latest/admin-guide/mm/damon/usage.html#sysfs-interface
and seeing /sys/kernel/ *****
- i found that there are battery module at /sys/module/battery, then found in in the kernel, 
linux/drivers/acpi/battery.c. it seems like what i have understood from module.h
- found https://www.kernel.org/doc/html/v6.8/core-api/kernel-api.html#module-support

### How To compile 
after visiting this https://stackoverflow.com/questions/9094237/whats-the-difference-between-usr-include-linux-and-the-include-folder-in-linux
found the `Documentation/kbuild/modules`

### How To Add Or Remove Modules From Kernel

---
I read `linux/kernel/module/kmod.c`, and i have seems code the looks like a cli application.
write `modprobe` in linux terminal worked, and `man modprobe` confirmed it.
---
seems to be that there are 2 locations for modules `/lib/modules/uname -r/` and  `/sys/modules`

### Install Module

`make -C $KDIR M=$PWD modules_install`
/home/yarin/CLionProjects/linux/arch/x86/boot/bzImage

## General Notes

---
Tried to compile the kernel and had the following error
> gelf.h: No such file or directory

the solution seems to fix the error https://www.reddit.com/r/voidlinux/comments/11pmp2g/i_cant_compile_the_kernel/?rdt=61937

---
Running linux with Qemu
https://www.qemu.org/docs/master/system/linuxboot.html
https://vccolombo.github.io/cybersecurity/linux-kernel-qemu-setup/


