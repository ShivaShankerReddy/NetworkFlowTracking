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


def print_packet_list(title, p_list):
    print(title)
    if len(p_list) == 0:
        print("None")
    else:
        for item in p_list.keys():
            print(item, "=>", p_list[item])


def print_received_packet_info(delay):
    print("Format: \nProtocol Source:port->Destination:port => num_packets\n")
    while True:
        time.sleep(delay)
        packet_list_lock.acquire()
        packet_counter = Counter(PACKET_LIST)
        PACKET_LIST.clear()
        packet_list_lock.release()
        print_packet_list("Packets:", packet_counter)


def run_sniffer():
    global s
    try:
        if len(sys.argv) != 2:
            print("Please enter an interface to sniff packets on")
            return

        # socket.ntohs(0x0003) allows to capture from tcp, udp, etc..
        socket_lock.acquire()
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((sys.argv[1], 0))

    except socket.error as err:
        print("Socket could not be created. Error Code :", err)
        return
    except Exception as err:
        print("Error: ", err)
        return
    finally:
        socket_lock.release()

    # Create a thread to print out number of incoming packets
    try:
        _thread.start_new_thread(print_received_packet_info, (PRINT_DELAY_SEC,))
    except Exception as err:
        print("Error unable to start thread:", err)
        return

    try:
        while True:
            # packet_data, address = s.recvfrom(65565)
            packet_data = s.recvfrom(65565)[0]

            # unpack the ethernet portion
            eth_header = struct.unpack(ETH_UNPACK_FORMAT, packet_data[0:ETH_HEADER_LEN])

            eth_type = socket.ntohs(eth_header[2])
            if eth_type != IPV4_NUMBER:
                continue

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
            packet_list_lock.acquire()
            if protocol_num == TCP_NUMBER or protocol_num == UDP_NUMBER:
                PACKET_LIST.append(
                    protocol_str
                    + " "
                    + str(source_addr)
                    + ":"
                    + str(source_port)
                    + "->"
                    + str(dest_addr)
                    + ":"
                    + str(dest_port)
                )
            else:
                PACKET_LIST.append(
                    protocol_str + " " + str(source_addr) + "->" + str(dest_addr)
                )
            packet_list_lock.release()
    except Exception:
        print("exit was received from main thread")


def main():
    # child threads are default daemon threads
    # once non daemon threads are gone the program exits
    _thread.start_new_thread(
        run_sniffer,
        ()
    )
    while input("To exit program type 'exit':\n") != "exit":
        continue
    try:
        socket_lock.acquire()
        socket.close(s.fileno())
        socket_lock.release()
    except Exception:
        print("Socket already closed")
    print("Exiting program")

if __name__ == "__main__":
    s = -1
    PACKET_LIST = []
    packet_list_lock = _thread.allocate_lock()
    socket_lock = _thread.allocate_lock()
    main()
