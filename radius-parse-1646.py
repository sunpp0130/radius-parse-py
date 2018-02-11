#!/usr/local/bin/python
 
from pyrad.packet import Packet
from pyrad.dictionary import Dictionary

from scapy.all import sniff, Radius
import sys

#if(len(sys.argv)>1):
#    eth=sys.argv[1]
#else:
#    eth="eth0"

if(len(sys.argv)>1):
    infile=sys.argv[1]
else:
    infile="sniff.pcap"

if(len(sys.argv)>2):
    outfile=sys.argv[2]
else:
    outfile="radius.log"

fout = open(outfile, 'w')

def parse_packet(packet):
    if(packet.haslayer(Radius)):
        radius_packet = str(packet[Radius])
        pkt = Packet(packet=radius_packet, dict=Dictionary("dictionary"))

        for key, value in pkt.iteritems():
            attr =  pkt._DecodeKey(key)
            value = pkt.__getitem__(attr)
            #print attr, value
	    fout.write("%s %s\n" % (attr, str(value)))
    else:
        #packet.show()
        pass

with open(outfile, 'w') as fout:
    sniff(offline=infile, prn=parse_packet, filter="udp", timeout= 1, store=0)

