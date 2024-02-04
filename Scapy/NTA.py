from scapy.all import rdpcap
#import os

#PCAPS = '/home/seshmaster/'
IP_MAC_Map = {}
SYN_Table = {}


def SYNFloodDetect(packet):

    try:
        flags = packet['TCP'].flags
        victim_IP = packet['IP'].dst
    except IndexError:
        return

    if victim_IP not in SYN_Table.keys():
        SYN_Table[victim_IP] = 0

    if flags == 'S':
        SYN_Table[victim_IP] += 1

    for IP in SYN_Table.keys():
        if SYN_Table[IP] > 10000:
            message = ("\nPossible SYN-Flood attack detected, victim = " + str(IP))
            print(message)




def ARPSpoofingDetect(packet):
    try:
        src_IP = packet['ARP'].psrc
        src_MAC = packet['Ether'].src
    except IndexError:
        return

    if src_MAC in IP_MAC_Map.keys():
        if IP_MAC_Map[src_MAC] != src_IP:
            try:
                old_IP = IP_MAC_Map[src_MAC]
            except:
                old_IP = "unknown"

            message = ("\nPossible ARP attack detected \n" +
                           "It is possible that the machine with IP address \n" +
                           str(old_IP) + " is pretending to be " + str(src_IP) +
                           "\n ")
            print(message)
    else:
        IP_MAC_Map[src_MAC] = src_IP


if __name__ == '__main__':
    file = rdpcap('TCP_DDOs.pcapng')
    sessions = file.sessions()
    for session in sessions:
        for packet in sessions[session]:
            ARPSpoofingDetect(packet)
            SYNFloodDetect(packet)
