MY_DRIVER_NAME=lyj_netfilter_cache

obj-m += $(MY_DRIVER_NAME).o

$(MY_DRIVER_NAME)-objs := netfilter_cache.o to_string.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
all:
	make -C $(KDIR) M=$(PWD) 
clean:
	make -C $(KDIR) M=$(PWD) clean
ins:
	insmod $(MY_DRIVER_NAME).ko
rins:
	rmmod $(MY_DRIVER_NAME).ko && insmod $(MY_DRIVER_NAME).ko
