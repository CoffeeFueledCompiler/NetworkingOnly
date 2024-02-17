from scapy.all import sniff, Ether, IP, ICMP, TCP, UDP
from datetime import datetime

def packet_handler(packet):
    print(datetime.now().strftime("%D %M %Y %H:%M:%S"))
    
    if Ether in packet:
        eth = packet[Ether]
        print('\nEthernet Frame:')
        print(f"\tSource: {eth.src}, Destination: {eth.dst}, Protocol: {eth.type}")

        if IP in packet:
            ip = packet[IP]
            print("\tIPV4 Packet:")
            print(f"\t\tTarget: {ip.dst}, Source: {ip.src}, Protocol: {ip.proto}")

            if ip.proto == 1 and ICMP in packet:
                icmp = packet[ICMP]
                print("\tICMP Packet:")
                print(f"\t\tType: {icmp.type}, Code: {icmp.code}")

            elif ip.proto == 6 and TCP in packet:
                tcp = packet[TCP]
                print("\tTCP Segment:")
                print(f"\t\tSource Port: {tcp.sport}, Destination Port: {tcp.dport}")
            
            elif ip.proto == 17 and UDP in packet:
                udp = packet[UDP]
                print("\tUDP Segment:")
                print(f"\t\tSource Port: {udp.sport}, Destination Port: {udp.dport}")

# Sniff packets using the filter parameter to capture all packets
sniff(filter="", prn=packet_handler, store=0)
