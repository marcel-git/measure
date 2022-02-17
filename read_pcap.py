import pyshark

#capture = list(pyshark.FileCapture(input_file='capture.pcap',display_filter='tcp.flags.syn==1 and tcp.flags.ack==1'))

capture2 = list (pyshark.FileCapture(input_file='test.pcap'))
for packet in capture2:
    print(packet)

    
