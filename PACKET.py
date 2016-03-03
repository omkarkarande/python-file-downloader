import IP, TCP

def getSYN(source_ip, destination_ip, packet_id, source_port, destination_port, SEQ_NUM, ACK_NUM, data, window_size):
    tcp_header = TCP.createTCPHeader(source_ip, destination_ip, source_port, destination_port, SEQ_NUM, ACK_NUM, data, window_size, [0, 1, 0, 0, 0, 0])
    ip_header = IP.createIPHeader(source_ip, destination_ip, packet_id, tcp_header, data)
    packet = ip_header + tcp_header + data
    return packet
    
def getACK(source_ip, destination_ip, packet_id, source_port, destination_port, SEQ_NUM, ACK_NUM, data, window_size):
    tcp_header = TCP.createTCPHeader(source_ip, destination_ip, source_port, destination_port, SEQ_NUM, ACK_NUM, data, window_size, [0, 0, 0, 0, 1, 0])
    ip_header = IP.createIPHeader(source_ip, destination_ip, packet_id, tcp_header, data)
    packet = ip_header + tcp_header + data
    return packet

def getFIN(source_ip, destination_ip, packet_id, source_port, destination_port, SEQ_NUM, ACK_NUM, data, window_size):
    tcp_header = TCP.createTCPHeader(source_ip, destination_ip, source_port, destination_port, SEQ_NUM, ACK_NUM, data, window_size, [1, 0, 0, 0, 1, 0])
    ip_header = IP.createIPHeader(source_ip, destination_ip, packet_id, tcp_header, data)
    packet = ip_header + tcp_header + data
    return packet
    
def getHTTP(source_ip, destination_ip, packet_id, source_port, destination_port, SEQ_NUM, ACK_NUM, data, window_size):
    tcp_header = TCP.createTCPHeader(source_ip, destination_ip, source_port, destination_port, SEQ_NUM, ACK_NUM, data, window_size, [0, 0, 0, 1, 1, 0])
    ip_header = IP.createIPHeader(source_ip, destination_ip, packet_id, tcp_header, data)
    packet = ip_header + tcp_header + data
    return packet
    