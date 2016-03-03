import socket, os
from struct import *

def unpackHeader(arp_header):
    return unpack("2s2s1s1s2s6s4s6s4s", arp_header)

def createARPRequest(source_ip, source_mac, target_ip):
    eth_hdr = pack("!6s6s2s", '\xff\xff\xff\xff\xff\xff', source_mac.replace(':','').decode('hex'), '\x08\x06')             
    arp_hdr = pack("!2s2s1s1s2s", '\x00\x01', '\x08\x00', '\x06', '\x04', '\x00\x01')          
    arp_sender = pack("!6s4s", source_mac.replace(':','').decode('hex'), socket.inet_aton(source_ip))
    arp_target = pack("!6s4s", '\x00\x00\x00\x00\x00\x00', socket.inet_aton(target_ip))
    
    return eth_hdr + arp_hdr + arp_sender + arp_target