#!/usr/bin/python3

import socket
import enum
import argparse
import os
import sys
import copy
import struct
import time

# BGPsec Open
bgpsec_open = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" \
              b"\x00\x6e" \
              b"\x01" \
              b"\x04" \
              b"\x30\x39" \
              b"\x00\xb4" \
              b"\xac\x12\x00\xc8" \
              b"\x51" \
              b"\x02\x06\x01\x04\x00\x01\x00\x01" \
              b"\x02\x02\x80\x00" \
              b"\x02\x02\x02\x00" \
              b"\x02\x02\x46\x00" \
              b"\x02\x06\x41\x04\x00\x00\x30\x39" \
              b"\x02\x06\x45\x04\x00\x01\x01\x01" \
              b"\x02\x09\x49\x07\x05\x62\x67\x70\x64\x31\x00" \
              b"\x02\x05\x07\x03\x08\x00\x01" \
              b"\x02\x05\x07\x03\x00\x00\x01" \
              b"\x02\x05\x07\x03\x08\x00\x02" \
              b"\x02\x05\x07\x03\x00\x00\x02" \
              b"\x02\x04\x40\x02\x00\x78"

bgpsec_open_ver = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" \
              b"\x00\x6e" \
              b"\x01" \
              b"\x04" \
              b"\x30\x39" \
              b"\x00\xb4" \
              b"\xac\x12\x00\xc8" \
              b"\x51" \
              b"\x02\x06\x01\x04\x00\x01\x00\x01" \
              b"\x02\x02\x80\x00" \
              b"\x02\x02\x02\x00" \
              b"\x02\x02\x46\x00" \
              b"\x02\x06\x41\x04\x00\x00\x30\x39" \
              b"\x02\x06\x45\x04\x00\x01\x01\x01" \
              b"\x02\x09\x49\x07\x05\x62\x67\x70\x64\x31\x00" \
              b"\x02\x05\x07\x03\x18\x00\x01" \
              b"\x02\x05\x07\x03\x10\x00\x01" \
              b"\x02\x05\x07\x03\x18\x00\x02" \
              b"\x02\x05\x07\x03\x10\x00\x02" \
              b"\x02\x04\x40\x02\x00\x78"

bgpsec_open_afi = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" \
              b"\x00\x6e" \
              b"\x01" \
              b"\x04" \
              b"\x30\x39" \
              b"\x00\xb4" \
              b"\xac\x12\x00\xc8" \
              b"\x51" \
              b"\x02\x06\x01\x04\x00\x01\x00\x01" \
              b"\x02\x02\x80\x00" \
              b"\x02\x02\x02\x00" \
              b"\x02\x02\x46\x00" \
              b"\x02\x06\x41\x04\x00\x00\x30\x39" \
              b"\x02\x06\x45\x04\x00\x01\x01\x01" \
              b"\x02\x09\x49\x07\x05\x62\x67\x70\x64\x31\x00" \
              b"\x02\x05\x07\x03\x08\x00\x03" \
              b"\x02\x05\x07\x03\x00\x00\x03" \
              b"\x02\x05\x07\x03\x08\x00\x04" \
              b"\x02\x05\x07\x03\x00\x00\x04" \
              b"\x02\x04\x40\x02\x00\x78"
# End of RIB
eor = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x17\x02\x00\x00\x00\x00"

# Keepalive
keepalive = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x13\x04"

# Notification
notification = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x15\x03\x05\x02"

my_as = b"\x30\x39"
my_as_pos = 20
bgp_id = b"\xac\x12\x00\xc8"
bgp_id_pos = 24
target_as = b"\x00\x11\x00\x00"
target_as_pos = 49

# Number of read updates. Only used for logging
upd_count = 1

log_level = 0

class States(enum.Enum):
    IDLE = 1
    CONNECT = 2
    ACTIVE = 3
    OPENSENT = 4
    OPENCONFIRM = 5
    ESTABLISHED = 6
    RECV = 7
    SEND = 8
    DONE = 9

# bgpsec_open = bgpsec_open[0:bgp_id_pos] +\
              # bgp_id +\
              # bgpsec_open[bgp_id_pos + len(bgp_id):]
# bgpsec_open = bgpsec_open[0:my_as_pos] +\
              # my_as +\
              # bgpsec_open[my_as_pos + len(my_as):]
# bgpsec_open = bgpsec_open[0:target_as_pos] +\
              # target_as +\
              # bgpsec_open[target_as_pos + len(target_as):]

def send_data(conn, addr, data):
    if log_level:
        print(data)

    conn.sendall(data)

def get_upd_ret(upd_file):
    global upd_count

    # Position of the file index
    curr_i = upd_file.tell()

    # Check for EoF
    last = upd_file.read(1)
    if last == b"" or last == b"\n":
        return None

    # Initialize the array
    byte_a = bytearray()

    # Jump to the len field
    upd_file.seek(curr_i + 16)

    # Read two bytes
    fb = struct.unpack("<B", upd_file.read(1))
    sb = struct.unpack("<B", upd_file.read(1))

    # Determine the length of the update
    upd_len = (fb[0] << 8) | sb[0]
    # print(f"Update length: {upd_len}")

    # Jump back to the beginning of the update
    upd_file.seek(curr_i)
    b = upd_file.read(upd_len)
    byte_a.extend(b)

    # Iterate trough the update
    # for i in range(0, upd_len):
        # Read one byte and append its integer value to byte_a
        #b = struct.unpack("<B", upd_file.read(1))
        # byte_a.append(b[0])

    # Add the update length to the file index position
    curr_i += upd_len

    if log_level == 1:
        print(f"Reading update {upd_count}", end='\r')
        upd_count += 1

    # return the byte array
    return byte_a


def get_upd(upd_file):
    # Position of the file index
    curr_i = 0
    # Number of read updates. Only used for logging
    upd_count = 1

    # Check for EoF
    while upd_file.read() != "":
        # Initialize the array with each iteration to empty it
        byte_a = bytearray()

        # Jump to the len field
        upd_file.seek(curr_i + 16)
        
        # Read two bytes
        fb = struct.unpack("<B", upd_file.read(1))
        sb = struct.unpack("<B", upd_file.read(1))

        # Determine the length of the update
        upd_len = (fb[0] << 8) | sb[0]
        #print(f"Update length: {upd_len}")

        # Jump back to the beginning of the update
        upd_file.seek(curr_i)
        b = upd_file.read(upd_len)
        byte_a.extend(b)

        # Iterate trough the update
        # for i in range(0, upd_len):
            # Read one byte and append its integer value to byte_a
            #b = struct.unpack("<B", upd_file.read(1))
            # byte_a.append(b[0])

        # Add the update length to the file index position
        curr_i += upd_len

        if log_level == 1:
            print(f"Reading update {upd_count}", end='\r')
            upd_count += 1

        # yield the byte array
        yield byte_a

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BGPsec 'Router'")
    parser.add_argument("host", help="Hostname or IP address to host from")
    parser.add_argument("port", type=int, help="Port to host from")
    parser.add_argument("target_ip", help="IP address of the peering router")
    parser.add_argument("target_port", type=int, help="Port of the peering router")
    parser.add_argument("upd_file", help="File containing BGP(sec) updates in binary format")
    parser.add_argument("-v", "--verbose", action="store_true", help="print more verbose debug output")
    args = parser.parse_args()

    if args.verbose:
        log_level = 1

    host = args.host
    port = args.port
    target_ip = args.target_ip
    target_port = args.target_port

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    STATE = States.CONNECT

    # To establish a BGP session, we first need to send an open message,
    # followed by a keepalive. Then, updates can be sent. At the end of
    # the stream of updates, an EoR should follow to indicate, no more
    # updates are coming. Last, to terminate the BGP session, we send a
    # notification message.
    with open(args.upd_file, "rb") as f:
        with sock as s:
            # Establish a TCP connection to the BGP router
            s.connect((target_ip, target_port))
            STATE = States.OPENSENT

            # Send and receive a BGP open message containing the BGPsec capabilities
            s.sendall(bgpsec_open)
            data = s.recv(4096)
            if log_level == 1: print(data)
            STATE = States.OPENCONFIRM

            # Send and receive a BGP keepalive message
            s.sendall(keepalive)
            data = s.recv(4096)
            if log_level == 1: print(data)
            STATE = States.ESTABLISHED

            # Wait for peer to send all its data. If we proceed to fast, we end up
            # closing the connection before the peer had time to wait for our updates
            # to come in
            # while s.recv(4096):
                # continue
            data = s.recv(4096)

            # upd will contain the bytes of all updates that are read via the iterator
            upds = bytearray()

            # Read the BGPsec updates from the iterator and append them to upd. The
            # reason behind this is that sending the BGPsec updates with each iteration
            # is very slow for some reason and creates a bottleneck this way
            while next_upd := get_upd_ret(f):
                # upds += bytearray(next_upd)
                s.sendall(bytes(next_upd))
                time.sleep(.002)
            if log_level == 1: print("") # clear last carriage return (\r)

            # Send the accumulated BGPsec updates
            # s.sendall(bytes(upds))

            # Send an EoR message to indicate the end of the BGPsec update stream
            s.sendall(eor)
            STATE = States.IDLE

            # Send a notification message to properly terminate the BGP session
            s.sendall(notification)
