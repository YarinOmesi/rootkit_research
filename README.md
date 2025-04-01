# rootkit_research
- [step 1](./STEP1.md)
- [step 2](./STEP2.md)
- [step 3](./STEP3.md)

## General Notes

---
Tried to compile the kernel and had the following error
> gelf.h: No such file or directory

the solution seems to fix the error https://www.reddit.com/r/voidlinux/comments/11pmp2g/i_cant_compile_the_kernel/?rdt=61937

---
### Running linux with Qemu
https://www.qemu.org/docs/master/system/linuxboot.html

https://vccolombo.github.io/cybersecurity/linux-kernel-qemu-setup/


got the following error `Failed to start Remount Root and Kernel File Systems`
solved it by adding 
```
CONFIG_CONFIGFS_FS=y
CONFIG_SECURITYFS=y
```
to linux .config



