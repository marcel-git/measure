import libpcap as pcap
import ctypes as ct
import sys

class Pcap:
    def __init__(self):
        self.errBuff = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)

        devlist = ct.POINTER(pcap.pcap_if_t)()
        pcap.findalldevs(ct.byref(devlist),self.errBuff)
        self.device = devlist[0].name
        pcap.freealldevs(devlist)

        self.errBuff[0] = b"\0"
    
    def activate(self):
        self.pd = pcap.create(self.device,self.errBuff)
        pcap.set_timeout(self.pd,1000)
        pcap.set_promisc(self.pd,0)
        status = pcap.set_tstamp_type(self.pd, pcap.PCAP_TSTAMP_ADAPTER)
        if status!=0:
            print(f"[~] Warning: {pcap.statustostr(status)}")
            print(f"[~] Consider using a device that supports hardware timestamps for better accuracy.")
        pcap.activate(self.pd)
        self.pdd = pcap.dump_open(self.pd, "capture.pcap".encode("utf-8"))
    
    def deactivate(self, count):
        while True:
            status = pcap.dispatch(self.pd, count, pcap.dump, ct.cast(self.pdd, ct.POINTER(ct.c_ubyte)))
            if status < 0:
                print(f"[!] Error: {pcap.statustostr(status)}")
                break
            if status == count:
                break

        pcap.close(self.pd)
        sys.stdout.flush()


