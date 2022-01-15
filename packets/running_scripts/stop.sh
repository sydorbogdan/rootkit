#!/bin/bash
sudo rmmod rootkit.ko
sudo python3 remove_line.py /etc/rc.local sudo modprobe rootkit
