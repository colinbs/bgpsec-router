#!/usr/bin/python3

import socket
import enum
import argparse
import os
import sys
import copy

# BGPsec Open
bgpsec_open = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x6a\x01\x04\x5b\xa0\x00\xb4\xac\x12\x00\x03\x4d\x02\x06\x01\x04\x00\x01\x00\x01\x02\x02\x80\x00\x02\x02\x02\x00\x02\x06\x41\x04\x00\x01\x00\x00\x02\x06\x45\x04\x00\x01\x01\x01\x02\x09\x49\x07\x05\x62\x67\x70\x64\x32\x00\x02\x05\x07\x03\x08\x00\x01\x02\x05\x07\x03\x00\x00\x01\x02\x05\x07\x03\x08\x00\x02\x02\x05\x07\x03\x00\x00\x02\x02\x04\x40\x02\x80\x78"

# End of RIB
eor = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x17\x02\x00\x00\x00\x00"

bgp_id = b"\xac\x12\x00\x04"
bgp_id_pos = 24
my_as = b"\x5b\xa1"
my_as_pos = 20
target_as = b"\x00\x11\x00\x00"
target_as_pos = 49

bgp_port = 179

log_level = 0

class States(enum.Enum):
    RECV = 1
    SEND = 2
    DONE = 3

bgpsec_open = bgpsec_open[0:bgp_id_pos] +\
              bgp_id +\
              bgpsec_open[bgp_id_pos + len(bgp_id):]
bgpsec_open = bgpsec_open[0:my_as_pos] +\
              my_as +\
              bgpsec_open[my_as_pos + len(my_as):]
bgpsec_open = bgpsec_open[0:target_as_pos] +\
              target_as +\
              bgpsec_open[target_as_pos + len(target_as):]

def send_data(conn, addr, data):
    if log_level:
        print(data)

    conn.sendall(data)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BGPsec 'Router'")
    parser.add_argument("host", help="hostname or IP address to host from")
    parser.add_argument("port", type=int, help="port to host from")
    parser.add_argument("target", help="IP address of the peering router")
    parser.add_argument("-v", "--verbose", action="store_true", help="print more verbose debug output")
    args = parser.parse_args()

    if args.verbose:
        log_level = 1

    host = args.host
    port = args.port
    target = args.target

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    STATE = States.RECV
    with sock as s:
        s.connect((target, bgp_port))
        s.bind((host, port))
        while True:
            s.listen(1)
            conn, addr = s.accept()
            with conn:
                if log_level: print(f"Connected by {addr[0]}:{addr[1]}")
                while STATE != States.DONE:
                    try:
                        if STATE == States.RECV:
                            data = conn.recv(1024)
                            STATE = States.SEND
                        elif STATE == States.SEND:
                            send_data(conn, addr[0], cache_response)
                            if log_level: print(f"Send Router Keys to {addr[0]}...", end=" ")
                            for key in key_vault:
                                send_data(conn, addr[0], key)

                            send_data(conn, addr[0], eor)
                            STATE = States.DONE
                    except:
                        STATE = States.DONE
                        break
                conn.close()
                if log_level: print(f"Closed connection to {addr[0]}:{addr[1]}")
                STATE = States.RECV
