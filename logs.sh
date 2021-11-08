#!/bin/bash

> logs.txt
dmesg | tail -30 | grep rootkit >> logs.txt