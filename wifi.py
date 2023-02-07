import pcap
import sys

sniffer = pcap.pcap(name=sys.argv[1], promisc=True, immediate=True, timeout_ms=3600)

for ts,pkt in sniffer:
    if pkt[24] == 128:
        mac = (':'.join('%02X' % i for i in pkt[40:46])
        if mac == sys.argv[2]:
            strength = int(pkt[18],16) - 256
            print(strength)
