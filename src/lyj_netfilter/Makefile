MY_DRIVER_NAME=lyj_netfilter

obj-m += $(MY_DRIVER_NAME).o

$(MY_DRIVER_NAME)-objs := sh_tcp.o to_string.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
all:
	make -C $(KDIR) M=$(PWD) 
clean:
	make -C $(KDIR) M=$(PWD) clean