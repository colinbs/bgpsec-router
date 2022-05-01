# bgpsec-router

This tool is used to send (malformed) BGP(sec) messages such as Open or Update messages to a peering software router implementation to check its behaviour. This is useful in case you don't want to modify an existing software router. Open messages are hard coded and can be adjusted. Real BGPsec Updates can be generated using [this tool](https://github.com/colinbs/bgpsec-path-gen) or can be found [here](https://wiki.wireshark.org/SampleCaptures#routing-protocols).

Please note that the bgpsec-"router" is rather static. Some configurations have to be hard coded and BGP messages have to be edited manually in order to tinker with them. So be sure which part of the hex-bytes-salad you are manipulating. The corresponding RFCs for [BGP](https://www.rfc-editor.org/rfc/rfc4271) and [BGPsec](https://www.rfc-editor.org/rfc/rfc8205), as well as a pcap dump of a real message are very useful for this matter.

# Usage
The bgpsec-router is a simple Python script that listens on a configurable local address and port. It requires the address and port of the software router it is supposed to send the messages to. The messages in question are read from a file that contains these messages in binary format.

General usage:

``./router.py [-v|--verbose] <local_ip> <local_port> <remote_ip> <remote_port> <upd_file>``

The `-v|--verbose` option enables debug output, such as received data from the peer.

Example usage:

``./router.py -v 127.0.0.1 3000 10.10.10.10 179 updates.bin``

Network and timing issues may cause the bgpsec-router to behave strange and inconsistent. So sending lots of messages to a peer is discuraged as it is very likely that many packages are lost.
