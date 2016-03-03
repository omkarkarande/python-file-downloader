import socket
from struct import *


def calculateChecksum(packet):
    checksum = 0
    #Check if the length of packet is a multiple of 2
    if len(packet) % 2 == 0:
        #Take 2 bytes at a time and add them
        for i in range(0, len(packet), 2):
            word = ord(packet[i]) + (ord(packet[i+1]) << 8)
            checksum += word
    else:
        #Odd number of bytes
        for i in range(0, len(packet) - 1, 2):
            word = ord(packet[i]) + (ord(packet[i+1]) << 8)
            checksum += word
            
        checksum += (ord(packet[len(packet) - 1]) & socket.ntohs(0xFF00))
        
    
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)
    
    #Ones Compliment
    checksum = ~checksum & 0xffff
    return checksum

def unpackHeader(header):
    return unpack('!BBHHHBBH4s4s' , header)

#;;;;;;;;;;;;;;;;;;;;;;;;;;;;CREATE NEW IP HEADER;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
def createIPHeader(source_ip, destination_ip, packet_id, tcp_header, data):
    
    #5 * 4 = 20
    ip_header_length = 5
    ip_version = 4
    ip_tos = 0
    #Length of the Entire Packet 
    ip_total_length = ip_header_length * 4 + len(tcp_header) + len(data)
    ip_pid = packet_id
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_checksum = 0
    ip_src = socket.inet_aton(source_ip)
    ip_dest = socket.inet_aton(destination_ip)
    
    ver_header = (ip_version << 4) + ip_header_length
    
    ip_header = pack('!BBHHHBBH4s4s', ver_header, ip_tos, ip_total_length, ip_pid, ip_frag_off, ip_ttl, ip_proto, ip_checksum, ip_src, ip_dest)
    
    checksum = calculateChecksum(ip_header)
    
    #Repackage IP header with corect checksum
    ip_header = pack('!BBHHHBB', ver_header, ip_tos, ip_total_length, ip_pid, ip_frag_off, ip_ttl, ip_proto) + pack('H', checksum) + pack('!4s4s', ip_src, ip_dest)
    return ip_header


def validateChecksum(iph, received_checksum):
    
    #Pack the header with checksum 0
    repackaged = pack(iph[0], iph[1], iph[2], iph[3], iph[4], iph[5], iph[6], 0, iph[8], iph[9])
    checksum = calculateChecksum(repackaged)
    
    if checksum == received_checksum:
        return True
    else:
        return False
    

def validateChecksumZero(ip_header):
    if calculateChecksum(ip_header) == 0:
        return True
    else:
        return False