#
# MODULENAME.c	the driver
# MODULENAME.h  the include file
# MODULENAME_test.c	the driver test source code
# MODULENAME_test	the driver test program
#
MODULENAME 	:= qat_contig_mem

KDIR		:= /lib/modules/$(shell uname -r)/build
PWD		:= $(shell pwd)

ifeq ($(shell uname -r|grep -c grsec-WR), 1)
AUTO_CONF=$(KDIR)/include/generated/autoconf.h
else ifeq ($(shell uname -r|grep -c el7), 1)
AUTO_CONF=$(KDIR)/include/generated/autoconf.h
else
AUTO_CONF=/usr/src/kernels/$(shell uname -r)/include/linux/autoconf.h
endif

ifdef KERNEL_SOURCE_ROOT
# Users who are cross compiling should export environment variable PATH_AUTOCNF
# to the correct path to file 'autoconf.h' for their target build
# prior to running this Makefile, to override, if necessary, the default given below,
# e.g., for a CentOS_7 target build this will be 'include/generated'
PATH_AUTOCNF?=include/linux
AUTO_CONF=$(KERNEL_SOURCE_ROOT)/$(PATH_AUTOCNF)/autoconf.h
KDIR=$(KERNEL_SOURCE_ROOT)
endif

CC		:= gcc -Wall -imacros $(AUTO_CONF)

ifeq ($(KERNELRELEASE),)
all:	$(MODULENAME)_test
all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
else
  obj-m	:= $(MODULENAME).o
endif

$(MODULENAME)_test: $(MODULENAME)_test.c
	$(CC) -g -o $(MODULENAME)_test $(MODULENAME)_test.c


load:
	insmod ./$(MODULENAME).ko

unload:
	rmmod $(MODULENAME)

test: all
	./$(MODULENAME)_test

clean:
	rm -f *.o *.ko Module.symvers modules.order *.mod.c .*.cmd $(MODULENAME)_test

