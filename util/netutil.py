import socket
import time
import pyshark
from dpkt import tcp, ip, ethernet, arp, pcap
from pylibpcap import get_first_iface,sniff,parse
from getmac import get_mac_address as gma


def get_mac_for_ip(iface,src, target):
    local_ip, local_eth_adr = src
    arp = ARP((local_ip,local_eth_adr),target=target)

    with socket.socket(socket.PF_PACKET, socket.SOCK_RAW) as sock:
        sock.bind((iface,ethernet.ETH_TYPE_ARP))
        
        print("test1")
        sniffobj = sniff(iface=iface, count=1, promisc=1, filters=f"arp and dst host {local_ip}")
        print("test2")
        sock.send(bytes(arp.build()))
        print("test3")
    for len, t , buf in sniffobj:
        print(len)
        parsed = parse.Packet(buf, len)
        return parsed.smac

def fetch_local_details():
    iface_name = get_first_iface()
    #Holt sich die eigene IP und MAC Adresse
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.connect(('10.255.255.255',1))
        local_ip = s.getsockname()[0]
    local_eth_adr = gma()
    return (iface_name,local_ip, local_eth_adr)

#Wrapper Klasse für dpkt TCP Pakete
class TCP:
    def __init__(self, sport, dport, flags, seq=0, ack=0):
        self.sport = sport
        self.dport = dport
        self.flags = sum(flags)
        self.seq = seq
        self.ack = ack

    def build(self):
        t = tcp.TCP(
            sport=self.sport,
            dport=self.dport,
            flags=self.flags,
            win=502,
            seq=self.seq,
            ack=self.ack,
        )
        return t

#Wrapper Klasse für dpkt IP Pakete
class IP:
    def __init__(self,src,dst,tcp):
        src_ip, src_mac = src
        dst_ip, dst_mac = dst
        self.src_ip = socket.inet_pton(socket.AF_INET, src_ip)
        self.src_mac = src_mac
        self.dst_ip = socket.inet_pton(socket.AF_INET, dst_ip)
        self.dst_mac = dst_mac
        self.data = tcp
        self.proto = ip.IP_PROTO_TCP

    def build(self):
        #build ip packet
        i = ip.IP(
            src=self.src_ip,
            dst=self.dst_ip,
            data=self.data,
            p=self.proto
        )

        #build ethernet frame
        e =  ethernet.Ethernet(
            src=self.src_mac,
            dst=self.dst_mac,
            data=i
        )
        return e

#Wrapper Klasse für dpkt ARP Pakete
class ARP:
    def __init__(self,src,target):
        local_ip, local_eth_adr = src
        self.local_ip = socket.inet_pton(socket.AF_INET, local_ip)
        self.local_eth_adr = local_eth_adr
        self.target_ip = socket.inet_pton(socket.AF_INET, target)
        self.broadcast_eth_adr = b'\xFF\xFF\xFF\xFF\xFF\xFF'

    def build(self):
        a = arp.ARP(
            spa=self.local_ip,
            sha=self.local_eth_adr,
            tpa=self.target_ip,
            tha=b'x00'*6,
            op=arp.ARP_OP_REQUEST
        )

        e = ethernet.Ethernet(
            src = self.local_eth_adr,
            dst = self.broadcast_eth_adr,
            data = a,
            type=ethernet.ETH_TYPE_ARP
        )
        return e
