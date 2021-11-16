import libpcap as pcap
import ctypes as ct
import sys

#Error buffer
errBuff = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)

#Get Network Device
devlist = ct.POINTER(pcap.pcap_if_t)()
pcap.findalldevs(ct.byref(devlist),errBuff)
device = devlist[0].name
pcap.freealldevs(devlist)

errBuff[0] = b"\0"

#Create pcap instance and start capturing
pd = pcap.create(device,errBuff)
pcap.set_timeout(pd,1000)
pcap.set_promisc(pd,0)
#pcap.set_snaplen(pd,65535)
status = pcap.set_tstamp_type(pd, pcap.PCAP_TSTAMP_ADAPTER)
if status!=0:
    print(f"[!] Warning: {pcap.statustostr(status)}")
    print(f"[!] Consider using a device that supports hardware timestamps for better accuracy.")
pcap.activate(pd)
#Open dump instance
pdd = pcap.dump_open(pd, "test.pcap".encode("utf-8"))

while True:
    status = pcap.dispatch(pd, 5, pcap.dump, ct.cast(pdd, ct.POINTER(ct.c_ubyte)))
    print(status)
    if status < 0:
        break
    if status != 0:
        print("{:d} packets seen after pcap.dispatch returns".format(status))
        ps = pcap.stat()
        pcap.stats(pd, ct.byref(ps))
        print("{:d} ps_recv, {:d} ps_drop, {:d} ps_ifdrop".format(ps.ps_recv, ps.ps_drop, ps.ps_ifdrop))
        break

pcap.close(pd)
sys.stdout.flush()
