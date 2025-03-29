KDIR ?= /lib/modules/`uname -r`/build
KBUILD_CFLAGS += -g -Wall

default:
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean

modules:
	$(MAKE) -C $(KDIR) M=$$PWD modules