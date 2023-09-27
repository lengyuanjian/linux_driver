MY_DRIVER_NAME=lgz_ch

obj-m += $(MY_DRIVER_NAME).o

SOURCES:=$(wildcard *.c)
OBJ:=$(patsubst %.c, %.o, $(SOURCES))

$(MY_DRIVER_NAME)-objs := lyj_ch.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
all:
	make -C $(KDIR) M=$(PWD) 
clean:
	make -C $(KDIR) M=$(PWD) clean
ins:
	insmod $(MY_DRIVER_NAME).ko
rmd:
	rmmod $(MY_DRIVER_NAME).ko
rins:
	rmmod $(MY_DRIVER_NAME).ko && insmod $(MY_DRIVER_NAME).ko
