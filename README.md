# Python Packet Sniffer
This Linux application opens a raw socket to receive IPv4 packets on a physical interface specified by command line arguments. It will count the number of packets received by each unique combination of source and destination and print it out periodically.

# Command

`sudo python3 sniffer.py <interface>`

For example:
`sudo python3 sniffer.py eth0`
