from scapy.all import *
from scapy.layers.http import HTTP
from scapy.layers.inet import TCP


def cb(pkt):
    if HTTP in pkt or TCP in pkt:
        print(pkt.show())


while True:
    sniff(prn=cb, count=1)
    time.sleep(2)