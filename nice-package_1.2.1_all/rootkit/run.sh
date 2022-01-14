#!/bin/bash

sudo rmmod rootkit.ko >> /dev/null 2>&1
make all >> /dev/null 2>&1
sudo insmod rootkit.ko >> /dev/null 2>&1
make clean >> /dev/null 2>&1

