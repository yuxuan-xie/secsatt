from scapy.all import *

MAC_BROADCAST = "FF:FF:FF:FF:FF:FF"

MAC_HOST = "00:0C:29:06:28:E5"
IP_HOST = "192.168.0.10"

MAC_EQUIPMENT = "00:0C:29:E9:42:B4"
IP_EQUIPMENT = "192.168.0.11"

MAC_MIDDLE = "00:0E:C6:78:0E:A0"
IP_MIDDLE = "192.168.0.9"

ip = IP();

ip.src = IP_HOST
ip.dst = IP_EQUIPMENT

tcp = TCP(flag = "S");
tcp.sport = 54950;
tcp.dport = 50000;

tcp.seq = 0
tcp.ack = 0

