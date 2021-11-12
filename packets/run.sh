#!/bin/bash

sudo rmmod rootkit.ko
make all
sudo insmod rootkit.ko
make clean

