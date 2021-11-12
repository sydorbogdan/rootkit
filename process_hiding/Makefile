obj-m += kity.o
all:
	sudo make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

#rm -rf *.o *.symvers *.mod *.order *.dwo
