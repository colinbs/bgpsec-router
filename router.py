#!/usr/bin/python3

import socket
import enum
import argparse
import os
import sys
import copy

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BGPsec 'Router'")
    parser.add_argument("host", help="Hostname or IP address to host from")
    parser.add_argument("port", type=int, help="Port to host from")
    parser.add_argument("target_ip", help="IP address of the peering router")
    parser.add_argument("target_port", type=int, help="Port of the peering router")
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
    with sock as s:
        s.connect((target_ip, target_port))
        STATE = States.OPENSENT
        s.sendall(bgpsec_open)
        data = s.recv(4096)
        print(repr(data))
        STATE = States.OPENCONFIRM
        s.sendall(keepalive)
        data = s.recv(4096)
        print(repr(data))
        STATE = States.ESTABLISHED
        data = s.recv(4096)
        print(repr(data))
        STATE = States.SEND
        s.sendall(eor)
        while data := s.recv(4096):
            print(repr(data))
        STATE = States.IDLE
        s.sendall(notification)
        sys.exit()
        # with conn:
            # if log_level: print(f"Connected by {addr[0]}:{addr[1]}")
            # while STATE != States.DONE:
                # try:
                    # if STATE == States.RECV:
                        # data = conn.recv(1024)
                        # STATE = States.SEND
                    # elif STATE == States.SEND:
                        # send_data(conn, addr[0], cache_response)
                        # if log_level: print(f"Send Router Keys to {addr[0]}...", end=" ")
                        # for key in key_vault:
                            # send_data(conn, addr[0], key)

                        # send_data(conn, addr[0], eor)
                        # STATE = States.DONE
                # except:
                    # STATE = States.DONE
                    # break
            # conn.close()
            # if log_level: print(f"Closed connection to {addr[0]}:{addr[1]}")
            # STATE = States.RECV
