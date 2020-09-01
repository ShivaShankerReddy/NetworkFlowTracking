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
import select
from collections import Counter

# Constants
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
protocol_table = {
    num: name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")
}


def get_protocol_name_by_num(p_num):
    try:
        name = protocol_table[p_num]
    except Exception:
        name = "UNKNOWN"
    return name


def print_received_packet_info(packet_counter):
    print("Packets:")
    if len(packet_counter) == 0:
        print("None")
    else:
        for item in packet_counter.keys():
            print(item, "=>", packet_counter[item])
    print("\n")

def process_recv_packet(s):
    # packet_data, address = s.recvfrom(65565)
    packet_data = s.recvfrom(65565)[0]
    # unpack the ethernet portion
    eth_header = struct.unpack(ETH_UNPACK_FORMAT, packet_data[0:ETH_HEADER_LEN])
    eth_type = socket.ntohs(eth_header[2])
    if eth_type != IPV4_NUMBER:
        return
    # unpack ip portion
    ip_header = struct.unpack(
        IP_UNPACK_FORMAT,
        packet_data[ETH_HEADER_LEN : ETH_HEADER_LEN + IP_HEADER_LEN_MIN],
    )
    # version is first 4 bits so if we bit shift 4 bits we ge the value
    # version = ip_header[0] >> 4
    # head len is next 4 bits so if we & with 0b00001111 we will get len
    ip_header_len = (ip_header[0] & 0xF) * 4
    protocol_num = ip_header[6]
    protocol_str = get_protocol_name_by_num(protocol_num)
    source_addr = socket.inet_ntoa(ip_header[8])
    dest_addr = socket.inet_ntoa(ip_header[9])
    if protocol_num == TCP_NUMBER:
        # unpack tcp portion
        tcp_header_index = ETH_HEADER_LEN + ip_header_len
        tcp_header = struct.unpack(
            TCP_UNPACK_FORMAT,
            packet_data[
                tcp_header_index : tcp_header_index + TCP_HEADER_LEN_MIN
            ],
        )
        source_port = tcp_header[0]
        dest_port = tcp_header[1]
    elif protocol_num == UDP_NUMBER:
        # unpack udp portion
        udp_header_index = ETH_HEADER_LEN + ip_header_len
        udp_header = struct.unpack(
            UDP_UNPACK_FORMAT,
            packet_data[udp_header_index : udp_header_index + UDP_HEADER_LEN],
        )
        source_port = udp_header[0]
        dest_port = udp_header[1]
    # Filter data into respective lists
    if protocol_num == TCP_NUMBER or protocol_num == UDP_NUMBER:
        packet_counter.update(
            [
                protocol_str
                + " "
                + str(source_addr)
                + ":"
                + str(source_port)
                + "->"
                + str(dest_addr)
                + ":"
                + str(dest_port)
            ]
        )
    else:
        packet_counter.update(
            [protocol_str + " " + str(source_addr) + "->" + str(dest_addr)]
        )

def run_sniffer():
    global s
    try:
        if len(sys.argv) != 2:
            print("Please enter an interface to sniff packets on")
            return

        # socket.ntohs(0x0003) allows to capture from tcp, udp, etc..
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((sys.argv[1], 0))
        inputs = [s]
        readable_data, writable_data, err_data = select.select(inputs, [], inputs, 10)

    except socket.error as err:
        print("Socket could not be created. Error Code :", err)
        return
    except Exception as err:
        print("Error: ", err)
        return

    print("Type 'exit' to exit program.")
    print("Format: \nProtocol Source:port->Destination:port => num_packets\n")
    continue_condition = True
    deadline = time.time() + PRINT_DELAY_SEC
    try:
        while continue_condition:
            if(time.time() >= deadline):
                print_received_packet_info(packet_counter)
                deadline = time.time() + PRINT_DELAY_SEC

            if select.select([sys.stdin,],[],[],0.0)[0] and input() == "exit":
                continue_condition = False

            for file_desc in readable_data:
                if(file_desc == s) :
                    process_recv_packet(s)

            if len(err_data) > 0 :
                continue_condition = False
            

    except Exception as err:
        print("Error: ", err)
    # close socket
    try: 
        print("Closing socket")
        socket.close(s.fileno())
    except:
        print("Error closing socket")

def main():
    run_sniffer()


if __name__ == "__main__":
    s = -1
    packet_counter = Counter()
    main()
