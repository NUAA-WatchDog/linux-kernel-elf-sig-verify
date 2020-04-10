obj-m += sv_hook_64.o
 
CURRENT_PATH:=$(shell pwd)
 
LINUX_KERNEL:=$(shell uname -r)
 
# LINUX_KERNEL_PATH:=/usr/src/linux-headers-$(LINUX_KERNEL)
LINUX_KERNEL_PATH:=$(CURRENT_PATH)/../
 
all:  
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) modules
clean:  
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) clean 
