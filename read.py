import pyshark

capture = list(pyshark.FileCapture(input_file='capture.pcap',display_filter='tcp.flags.syn==1 and tcp.flags.ack==1'))

ts1, ts2 = float(capture[0].sniff_timestamp), float(capture[-1].sniff_timestamp)

print(f"[+] 1st Probe returned at {ts1}")
print(f"[+] 2nd Probe returned at {ts2}")
print(f"[+] Delta: {((ts2-ts1)*1000)}ms")
    