#!/usr/bin/python

# set up iptables with 'iptables -I INPUT -p tcp --dport 443 -s 192.0.2.1 -j NFQUEUE --queue-num 1'
# needs scapy 2.4 or newer for TLS. for compliant implementations this type of modification should
# result in a failed TLS handshake, but you never know...

from scapy.all import *
from netfilterqueue import NetfilterQueue


def modify_packets(pkt):
    parsed = IP(pkt.get_payload())
    if TCP in parsed:
        if TLS_Ext_MaxFragLen in parsed: # an extension that, if present, will be modified
            print("before: %s" % repr(parsed))
            parsed[TLS_Ext_MaxFragLen].type = 21 # 21 is "padding"
            parsed = IP(parsed) # re-parse the packet to make changing the other values easier
            parsed[TLS_Ext_Padding].padding = chr(0) * parsed[TLS_Ext_Padding].len # "len" should only ever be "1" for MaxFragLen, but just in case...
            del parsed[IP].chksum # make scapy re-compute these checksums
            del parsed[TCP].chksum
            pkt.set_payload(str(parsed)) # insert the modified packet back in to iptables
            print("after: %s" % repr(parsed))
    pkt.accept()


load_layer("tls")
nfqueue = NetfilterQueue()
nfqueue.bind(1, modify_packets)

try:
    nfqueue.run()
except KeyboardInterrupt:
    print("")

nfqueue.unbind()
