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