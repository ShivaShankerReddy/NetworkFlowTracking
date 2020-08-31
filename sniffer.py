# Victor Phan
# August 31, 2020

# This flow tracking linux application uses a raw socket
# to receive IPv4 packets on a user specified interface.
# For each packet received the application will

# Parse the following:
# IP source
# IP destination
# IP protocol
# source UDP/TCP port (if protocol is UDP or TCP)
# destination UDP/TCP port (if protocol is UDP or TCP)

# The application also:

# Counts the number of packets received per combination of values
# Every 10 seconds, prints the counts of each packet flow
# to standard out in a human-readable form

# Create a raw socket

import socket
import sys
import fcntl
import struct
import time
import _thread
from collections import Counter

PRINT_DELAY_SEC = 10
ETH_HEADER_LEN = 14
IP_HEADER_LEN_MIN = 20
TCP_HEADER_LEN_MIN = 20
UDP_HEADER_LEN = 8

ETH_UNPACK_FORMAT = "!6s6sH"
IP_UNPACK_FORMAT = "!BBHHHBBH4s4s"
TCP_UNPACK_FORMAT = "!HHLLBBHHH"
UDP_UNPACK_FORMAT = "!HHHH"

IPV4_NUMBER = 8
TCP_NUMBER = 6
UDP_NUMBER = 17

UDP_PACKET_LIST = []
TCP_PACKET_LIST = []
OTHER_PACKET_LIST = []

def print_packet_list(title, p_list):
    print(title)
    if(len(p_list) == 0):
        print("None")
    else:
        for item in p_list.keys():
            print(item, "=>", p_list[item])


def print_received_packet_info(delay):
    print("Format: \nSource:port -> Destination:port => num_packets\n")
    while True:
        time.sleep(delay)
        udp_counter = Counter(UDP_PACKET_LIST)
        tcp_counter = Counter(TCP_PACKET_LIST)
        other_counter = Counter(OTHER_PACKET_LIST)
        UDP_PACKET_LIST.clear()
        TCP_PACKET_LIST.clear()
        OTHER_PACKET_LIST.clear()
        print_packet_list("UDP Packets:", udp_counter)
        print_packet_list("TCP Packets:", tcp_counter)
        print_packet_list("OTHER Packets:", other_counter)

try:
    if len(sys.argv) != 2:
        print("Please enter an interface to sniff packets on")
        sys.exit()

    # socket.ntohs(0x0003) allows to capture from tcp, udp, etc..
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind((sys.argv[1], 0))

except socket.error as err:
    print("Socket could not be created. Error Code :", err)
    sys.exit()
except Exception as err:
    print("Error: ", err)
    sys.exit()

try:
    _thread.start_new_thread(print_received_packet_info, (PRINT_DELAY_SEC,))
except Exception as err:
    print("Error unable to start thread:", err)
    
while True:
    packet_data, address = s.recvfrom(65565)

    # unpack the ethernet portion
    eth_header = struct.unpack(ETH_UNPACK_FORMAT, packet_data[0:ETH_HEADER_LEN])

    # 8 means ipv4
    eth_type = socket.ntohs(eth_header[2])

    if eth_type != IPV4_NUMBER:
        continue

    # unpack ip portion
    ip_header = struct.unpack(
        IP_UNPACK_FORMAT,
        packet_data[ETH_HEADER_LEN : ETH_HEADER_LEN + IP_HEADER_LEN_MIN],
    )
    version = ip_header[0] >> 4
    ip_header_len = (ip_header[0] & 0xF) * 4
    protocol = ip_header[6]
    source_addr = socket.inet_ntoa(ip_header[8])
    dest_addr = socket.inet_ntoa(ip_header[9])
    if (protocol == TCP_NUMBER):
        tcp_header_index = ETH_HEADER_LEN + ip_header_len
        tcp_header = struct.unpack(
            TCP_UNPACK_FORMAT,
            packet_data[tcp_header_index : tcp_header_index + TCP_HEADER_LEN_MIN],
        )
        source_port = tcp_header[0]
        dest_port = tcp_header[1]
    elif (protocol == UDP_NUMBER):
        udp_header_index = ETH_HEADER_LEN + ip_header_len
        udp_header = struct.unpack(
            UDP_UNPACK_FORMAT,
            packet_data[udp_header_index : udp_header_index + UDP_HEADER_LEN],
        )
        source_port = udp_header[0]
        dest_port = udp_header[1]
    
    #Filter data into respective lists
    if(protocol == TCP_NUMBER):
        TCP_PACKET_LIST.append(str(source_addr) + ":" + str(source_port) + "->" + str(dest_addr) + ":" + str(dest_port))
    elif(protocol == UDP_NUMBER):
        UDP_PACKET_LIST.append(str(source_addr) + ":" + str(source_port) + "->" + str(dest_addr) + ":" + str(dest_port))
    else:
        OTHER_PACKET_LIST.append(str(source_addr) + "->" + str(dest_addr))
