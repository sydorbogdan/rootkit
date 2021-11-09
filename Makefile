KERNELDIR:=/lib/modules/$(shell uname -r)/build

obj-m = rootkit.o
rootkit-objs = main.o

all: rootkit.ko

rootkit.ko: main.c
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean