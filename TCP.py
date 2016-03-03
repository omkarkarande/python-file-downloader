import socket
from struct import *


#;;;;;;;;;;;;;;;;;;;;;;;;;;;;CHECKSUM CALCULATION;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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

#;;;;;;;;;;;;;;;;;;;;;;;;;;;;;UNPACKER;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
def unpackHeader(header):
    return unpack('!HHLLBBHHH' , header)

#;;;;;;;;;;;;;;;;;;;;;;;;;;;;CREATE NEW IP HEADER;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
def createTCPHeader(source_ip, destination_ip, source_port, destination_port, SEQ_NUM, ACK_NUM, data, WND_SIZE, flags):
    
    #Flip to send the responce for the packet
    sequence_number = ACK_NUM
    ack_number = SEQ_NUM
    #5 * 4 = 20
    data_offset = 5
    
    window_size = socket.htons(WND_SIZE)
    checksum = 0
    urg_pointer = 0
    
    off_res = (data_offset << 4) + 0
    flags_field = flags[0] + (flags[1] << 1) + (flags[2] << 2) + (flags[3] << 3) + (flags[4] << 4) + (flags[5] << 5)
    
    #Package tcp header with checksum = 0
    tcp_header_zero_check = pack('!HHLLBBHHH', source_port, destination_port, sequence_number, ack_number, off_res, flags_field, window_size, checksum, urg_pointer)
    
    
    #pseudo header for checksum calculation
    ip_src = socket.inet_aton(source_ip)
    ip_dest = socket.inet_aton(destination_ip)
    placeholder_field = 0
    protocol = socket.IPPROTO_TCP
    length = len(tcp_header_zero_check) + len(data)
    
    pseudo = pack('!4s4sBBH', ip_src, ip_dest, placeholder_field, protocol, length)
    pseudo_packet = pseudo + tcp_header_zero_check + data
    
    checksum = calculateChecksum(pseudo_packet)
    
    #Renuild the TCP header with the correct checksum
    tcp_header = pack('!HHLLBBH', source_port, destination_port, sequence_number, ack_number, off_res, flags_field, window_size) + pack('H', checksum) + pack('!H', urg_pointer)
    return tcp_header
    

def validateChecksum(tcph, data, ip_src, ip_dest, received_checksum):
    
    #Repackage with checksum = 0
    repackaged = pack('!HHLLBBHHH', tcph[0], tcph[1], tcph[2], tcph[3], tcph[4], tcph[5], tcph[6], 0, tcph[8])
    
    #pseudo
    placeholder_field = 0
    protocol = socket.IPPROTO_TCP
    length = len(repackaged) + len(data)
    
    pseudo = pack('!4s4sBBH', ip_src, ip_dest, placeholder_field, protocol, length)
    pseudo_packet = pseudo + repackaged + data
    
    checksum = calculateChecksum(pseudo_packet)
    
    if checksum == received_checksum:
        return True
    else:
        return False
    

def validateChecksumZero(tcp_packet):
    if calculateChecksum(tcp_packet) == 0:
        return True
    else:
        return False