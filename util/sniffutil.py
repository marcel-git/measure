import libpcap as pcap
import ctypes as ct
import sys
from datetime import timedelta
import os

ts = []

class Pcap:
    def __init__(self):

        self.errBuff = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)

        self.device = b'eno1'

        self.errBuff[0] = b"\0"

    #Erzeugt pcap Instanz um die Probes mit Timestamps zu versehen
    def activate(self):
        ts.clear()

        self.pd = pcap.create(self.device,self.errBuff)

        pcap.set_timeout(self.pd,1000)
        pcap.set_promisc(self.pd,0)

        status = pcap.set_tstamp_type(self.pd, pcap.PCAP_TSTAMP_ADAPTER_UNSYNCED)

        if status!=0:
            print(f"[~] Warning: {pcap.statustostr(status)}")
            print(f"[~] Timestamping set to HOST")

        pcap.activate(self.pd)

        #Erstelle filter, sodass nur die Probes eingefangen werden
        fcode = pcap.bpf_program()
        cmdbuf = "tcp[tcpflags] == tcp-syn|tcp-ack and port 55555".encode('utf-8')

        if pcap.compile(self.pd,ct.byref(fcode),cmdbuf,1,pcap.PCAP_NETMASK_UNKNOWN)<0:
            print("[!] Compilation of filter failed!")
        if pcap.setfilter(self.pd,ct.byref(fcode))<0:
            print("[!] Setting filter failed!")
        nonblock = 1
        if pcap.setnonblock(self.pd,nonblock,self.errBuff)==-1:
            print("[!] Setting mode to nonblocking failed!")

    #Stoppt das fangen via pcap und wertet die empfangenen Pakete aus
    def deactivate(self, count):
        while True:
            packet_count = ct.c_int(0)
            #Für jedes gefangene packet wird die Handler Funktion aufgerufen
            status = pcap.dispatch(self.pd, count, self.packetHandler, ct.cast(ct.pointer(packet_count), ct.POINTER(ct.c_ubyte)))

            if status < 0:
                print(f"[!] Error: {pcap.statustostr(status)}")
                break
            if status == count:
                print(f"[+] {status} packets captured")
                break

        pcap.close(self.pd)
        sys.stdout.flush()
        return ts

    #Handler für die dispatch Funktion
    @pcap.pcap_handler
    def packetHandler(arg, hdr, pkt):
        #Paket enthält die TS als ts struct in Sekunden und Mikrosekunden 
        ts.append(float(str(hdr.contents.ts.tv_sec)+"."+str(hdr.contents.ts.tv_usec)))

