import socket
from struct import *

def unpackHeader(header):
    return unpack('!6s6sH', header)
    
    
def createEthernetHeader(destination_mac, source_mac, proto):
    #print destination_mac.replace(":","").decode('hex')
    #print source_mac.replace(":","").decode('hex')
    eth_header = pack('!6s6sH', destination_mac.replace(":","").decode('hex'), source_mac.replace(":","").decode('hex'), proto)
    return eth_header


def ethernet_address(s):
    addr = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(s[0]) , ord(s[1]) , ord(s[2]), ord(s[3]), ord(s[4]) , ord(s[5]))
    return addr
    
def getEthernetHeader(header):
    eth_header = unpackHeader(header)
    return ethernet_address(header[0:6]), ethernet_address(header[6:12]), socket.ntohs(eth_header[2])