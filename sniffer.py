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

ETH_HEADER_LEN = 14
ETH_UNPACK_FORMAT = "!6s6sH"
IP_UNPACK_FORMAT = "!BBHHHBBH4s4s"
IP_HEADER_LEN = 20

try:
    if (len(sys.argv) != 2):
        print("Please enter an interface to sniff packets on")
        sys.exit()

    # socket.ntohs(0x0003) allows to capture from tcp, udp, etc..
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind((sys.argv[1],0))

except socket.error as err:
    print("Socket could not be created. Error Code :", err)
    sys.exit()
except Exception as err:
    print("Error: ", err)
    sys.exit()

i = 1
while i < 10:
    packet_data, address = s.recvfrom(65565)

    # unpack the ethernet portion
    eth_header = struct.unpack(ETH_UNPACK_FORMAT, packet_data[0:ETH_HEADER_LEN])

    # 8 means ipv4
    eth_type = socket.ntohs(eth_header[2])

    # unpack ip portion
    ip_header = struct.unpack(IP_UNPACK_FORMAT, packet_data[ETH_HEADER_LEN:ETH_HEADER_LEN + IP_HEADER_LEN])

    protocol = ip_header[6]
    s_addr = socket.inet_ntoa(ip_header[8])
    d_addr = socket.inet_ntoa(ip_header[9])

    i = i + 1

