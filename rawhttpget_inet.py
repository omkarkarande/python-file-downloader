import sys
import socket, random, operator, time, fcntl, os
import IP, TCP, HTTP, PACKET
from struct import *

#;;;;;;;;;;;;;;;;;;;;;;SENDER SOCKET;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
def getSenderSocket():
    try:
        sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error, error:
        print "ERROR! Cannot create sender socket\nCODE: " + str(error[0]) + " MESSAGE: " + error[1]
        sys.exit(1)

    return sender
#;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

#;;;;;;;;;;;;;;;;;;;;;;RECEIVER SOCKET;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
def getReceiverSocket():
    try:
        receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error, error:
        print "ERROR! Cannot create receiver socket\nCODE: " + str(error[0]) + " MESSAGE: " + error[1]
        sys.exit(1)

    return receiver
#;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

#       METHODS FOR OBTAINING THE SOURCE IP AND DESTINATION IP

#;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
def getDestinationIP(host):
    return socket.gethostbyname(host)

def getSourceIP():
    connector = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connector.connect(('google.com', 0))
    return connector.getsockname()[0]

#;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

#        RETURNS THE HOST PATH PROTOCOL PORT AND FILENAME

#;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
def parseURL(url):

    protocol = ''
    host = ''
    port = 80
    path = '/'
    filename = 'index.html'

    #Get the protocol from the url if present
    if url.find('://') != -1:
        protocol = url[:url.find('://')]
        #Trim the protol from the url
        url = url[url.find('://') + 3:]
    else:
        protocol = 'http'


    #Get the host name from the url
    if url.find('/') != -1:
        host = url[:url.find('/')]
        #Trim the host from the url
        #get the path
        path = url[url.find('/'):]
        url = url[url.find('/') + 1:]
    else:
        host = url


    #Extract port number if present in the hostname
    if host.find(':') != -1:
        port = int(host[host.find(':') + 1:])
        host = host[:host.find(':')]


    #Extract the filename from the url
    if url.find('/') != -1:
        if not url.endswith('/'):
            filename = url[url.rfind('/') + 1:]
            #Remove the GET query if present
            if filename.find('?') != -1:
                filename = filename[:filename.find('?')]

    return protocol, host, port, path, filename


#;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;PAACKET VALIDATION;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
def validatePacket(packet):

    if not IP.validateChecksumZero(packet[0:20]):
        return False, "IP"
    else:
        print "IP VALIDATION: SUCCESS"

    ip_header = IP.unpackHeader(packet[0:20])
    #Get Length of IP header
    ip_ver = ip_header[0] >> 4
    ip_header_length = ip_header[0] & 0xF
    ip_length = ip_header_length * 4

    tcp_packet = packet[ip_length:]
    pseudo = pack('!4s4sBBH', ip_header[8], ip_header[9], 0, socket.IPPROTO_TCP, len(tcp_packet))

    if not TCP.validateChecksumZero(pseudo + tcp_packet):
        return False, "TCP"
    else:
        print "TCP VALIDATION: SUCCESS"

    return True, ""

#;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;MAIN;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
URL = ""
SOURCE_IP = ""
DESTINATION_IP = ""

#Check if argument length is no less than 2
if len(sys.argv) < 2:
    print "USAGE: %s <url>" % sys.argv[0]
    sys.exit(2)

#Get the url from the argument
URL = sys.argv[1]
content = {}

#Parse the URL and get all parameters needed
PROTOCOL, HOST, DESTINATION_PORT, PATH, FILENAME = parseURL(URL.strip())

#Get the source and destination IP addresses
SOURCE_IP = getSourceIP()
DESTINATION_IP = getDestinationIP(HOST)

#Any random source port
SOURCE_PORT = random.randint(1024, 65500)

print 'URL:\t\t\t', URL
print 'PROTOCOL:\t\t', PROTOCOL
print 'HOST:\t\t\t', HOST
print 'PATH:\t\t\t', PATH
print 'FILENAME:\t\t', FILENAME
print 'SOURCE IP:\t\t', SOURCE_IP
print 'SOURCE PORT:\t\t', SOURCE_PORT
print 'DESTINATION IP:\t\t', DESTINATION_IP
print 'DESTINATION PORT:\t', DESTINATION_PORT


#TCP PARAMETERS
WINDOW_SIZE = 1000
SEQ_NUM = 1
SEQ_START = 1
SEQ_END = 1
ACK_NUM = random.randint(1024, 65500)
PACKET_ID = random.randint(1024, 65500)
TIMEOUT_TIME_IN_SECONDS = 60

CWND = 1
SSTHRESH = WINDOW_SIZE

#Create sockets
sender_socket = getSenderSocket()
receiver_socket = getReceiverSocket()
#Set the receiver to non blocking
receiver_socket.settimeout(1)


#;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

#                                   3-WAY HANDSHAKE

#;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
syn_packet = PACKET.getSYN(SOURCE_IP, DESTINATION_IP, PACKET_ID, SOURCE_PORT, DESTINATION_PORT, SEQ_NUM, ACK_NUM, "", WINDOW_SIZE)
sender_socket.sendto(syn_packet, (DESTINATION_IP, DESTINATION_PORT))
#Time when the packet was sent
packet_sent_time = time.time()

#WAIT FOR A SYN_ACK
while True:
    try:
        packet = receiver_socket.recvfrom(65565)
        packet = packet[0]
        #print packet

        validation_status, faulty_packet = validatePacket(packet)

        if validation_status:
            #IP header bytes
            ip_header = IP.unpackHeader(packet[0:20])
            if socket.inet_ntoa(ip_header[8]) == DESTINATION_IP and socket.inet_ntoa(ip_header[9]) == SOURCE_IP:
                #Get Length of IP header
                ip_ver = ip_header[0] >> 4
                ip_header_length = ip_header[0] & 0xF
                ip_length = ip_header_length * 4

                tcp_header = TCP.unpackHeader(packet[ip_length: ip_length + 20])
                ack = (tcp_header[5] & 0x10) >> 4
                syn = (tcp_header[5] & 0x02) >> 1

                if ack == 1 and syn == 1 and tcp_header[0] == DESTINATION_PORT and tcp_header[1] == SOURCE_PORT and tcp_header[3] == (ACK_NUM + 1):
                    #SYN-ACK received
                    SEQ_NUM = tcp_header[2] + 1
                    SEQ_START = tcp_header[2]
                    ACK_NUM = tcp_header[3]
                    packet_sent_time = time.time()

                    #ACKd
                    if CWND < SSTHRESH:
                        CWND += 1


                    break
        else:
            print "BAD CHECKSUM: ", faulty_packet

    except socket.timeout:
        pass

    #Timeout check and retransmission
    current_time = time.time()
    if current_time - packet_sent_time >= TIMEOUT_TIME_IN_SECONDS:
        #retransmit
        syn_packet = PACKET.getSYN(SOURCE_IP, DESTINATION_IP, PACKET_ID, SOURCE_PORT, DESTINATION_PORT, SEQ_NUM, ACK_NUM, "", WINDOW_SIZE)
        sender_socket.sendto(syn_packet, (DESTINATION_IP, DESTINATION_PORT))
        #Update sending time
        packet_sent_time = time.time()

        #Resent CWND
        CWND = 1


#Send an ACK to the Server
ack_packet = PACKET.getACK(SOURCE_IP, DESTINATION_IP, PACKET_ID, SOURCE_PORT, DESTINATION_PORT, SEQ_NUM, ACK_NUM, "", WINDOW_SIZE)
sender_socket.sendto(ack_packet, (DESTINATION_IP, DESTINATION_PORT))

#SEND HTTP PACKET
request = PACKET.getHTTP(SOURCE_IP, DESTINATION_IP, PACKET_ID, SOURCE_PORT, DESTINATION_PORT, SEQ_NUM, ACK_NUM, HTTP.createHTTPHeader(PATH, HOST), WINDOW_SIZE)
sender_socket.sendto(request, (DESTINATION_IP, DESTINATION_PORT))
#Time when the packet was sent
last_packet_sent_time = time.time()

#Listen for all incoming data packets
transaction_complete = False
last_packet = request

while True:
    try:
        packet = receiver_socket.recvfrom(65565)
        packet = packet[0]
	print len(packet)
        validation_status, faulty_packet = validatePacket(packet)

        if validation_status:
            ip_header = IP.unpackHeader(packet[0:20])
            if socket.inet_ntoa(ip_header[8]) == DESTINATION_IP and socket.inet_ntoa(ip_header[9]) == SOURCE_IP:

                #Get Length of IP header
                ip_ver = ip_header[0] >> 4
                ip_header_length = ip_header[0] & 0xF
                ip_length = ip_header_length * 4

                tcp_header = TCP.unpackHeader(packet[ip_length: ip_length + 20])
                if tcp_header[0] == DESTINATION_PORT and tcp_header[1] == SOURCE_PORT and SEQ_START <= tcp_header[2]:

                    if SEQ_NUM == tcp_header[2]:

                        ack = (tcp_header[5] & 0x10) >> 4
                        psh = (tcp_header[5] & 0x08) >> 3
                        syn = (tcp_header[5] & 0x02) >> 1
                        fin = (tcp_header[5] & 0x01)

                        tcp_hl = tcp_header[4] >> 4
                        tcp_length = tcp_hl * 4

                        header_size = ip_length + tcp_length
                        data_size = len(packet) - header_size

                        data = str(packet[header_size:])

                        #Storing the Data from the packets
                        if len(data) != 0:
                            if data.startswith('HTTP/1.'):
                                if data[data.find(' ') + 1:data.find(' ') + 4] == '200':
                                    #HTTP OK Received.
                                    #Store remaining data and initiate teardown
                                    if data.find('\r\n\r\n') != -1:
                                        data = data[data.find('\r\n\r\n') + 4:]
                                    else:
                                        print "HTTP response malformed (no new line)"
                                        break
                                else:
                                    print "NON 200 HTTP CODE RECEIVED. Exiting..."
                                    sys.exit(1)

                            if content.has_key(SEQ_NUM) == False:
                                content[SEQ_NUM] = data

                        if fin == 1 and ack == 1 and transaction_complete == False:
                            SEQ_NUM = tcp_header[2] + data_size
                            ACK_NUM = tcp_header[3]

                            ack_packet = PACKET.getACK(SOURCE_IP, DESTINATION_IP, PACKET_ID, SOURCE_PORT, DESTINATION_PORT, SEQ_NUM, ACK_NUM, "", WINDOW_SIZE)
                            sender_socket.sendto(ack_packet, (DESTINATION_IP, DESTINATION_PORT))

                            fin_packet = PACKET.getFIN(SOURCE_IP, DESTINATION_IP, PACKET_ID, SOURCE_PORT, DESTINATION_PORT, SEQ_NUM, ACK_NUM, "", WINDOW_SIZE)
                            sender_socket.sendto(fin_packet, (DESTINATION_IP, DESTINATION_PORT))

                            last_packet = fin_packet
                            last_packet_sent_time = time.time()
                            transaction_complete = True

                            #ACKd
                            if CWND < SSTHRESH:
                                CWND += 1


                        elif fin == 1 and ack == 1 and transaction_complete == True:
                            SEQ_NUM = tcp_header[2] + data_size
                            ACK_NUM = tcp_header[3]

                            ack_packet = PACKET.getACK(SOURCE_IP, DESTINATION_IP, PACKET_ID, SOURCE_PORT, DESTINATION_PORT, SEQ_NUM, ACK_NUM, "", WINDOW_SIZE)
                            sender_socket.sendto(ack_packet, (DESTINATION_IP, DESTINATION_PORT))

                            last_packet = ack_packet
                            last_packet_sent_time = time.time()

                            #ACKd
                            if CWND < SSTHRESH:
                                CWND += 1

                            break

                        elif transaction_complete:
                            if fin == 1 and ack == 1 and psh == 1:
                                SEQ_NUM = tcp_header[2]
                                ACK_NUM = tcp_header[3]

                                ack_packet = PACKET.getACK(SOURCE_IP, DESTINATION_IP, PACKET_ID, SOURCE_PORT, DESTINATION_PORT, SEQ_NUM, ACK_NUM, "", WINDOW_SIZE)
                                sender_socket.sendto(ack_packet, (DESTINATION_IP, DESTINATION_PORT))

                                last_packet = ack_packet
                                last_packet_sent_time = time.time()

                                #ACKd
                                if CWND < SSTHRESH:
                                    CWND += 1

                                break

                        elif fin != 1:
                            SEQ_NUM = tcp_header[2] + data_size
                            ACK_NUM = tcp_header[3]

                            SEQ_END = SEQ_NUM

                            ack_packet = PACKET.getACK(SOURCE_IP, DESTINATION_IP, PACKET_ID, SOURCE_PORT, DESTINATION_PORT, SEQ_NUM, ACK_NUM, "", WINDOW_SIZE)
                            sender_socket.sendto(ack_packet, (DESTINATION_IP, DESTINATION_PORT))

                            last_packet = ack_packet
                            last_packet_sent_time = time.time()
                            #ACKd
                            if CWND < SSTHRESH:
                                CWND += 1

                    else:
                        #Packet drop
                        CWND = 1

        else:
            print "BAD CHECKSUM: ", faulty_packet

    except socket.timeout:
        pass

    #Timeout check and retransmission
    current_time = time.time()
    if current_time - last_packet_sent_time >= TIMEOUT_TIME_IN_SECONDS:
        #retransmit
        sender_socket.sendto(last_packet, (DESTINATION_IP, DESTINATION_PORT))
        last_packet_sent_time = time.time()

        #Reset
        CWND = 1


#File Handling
with open(FILENAME, "w") as f:

    #Remove unwanted entries
    filtered = {}
    for key in content:
        if key >= SEQ_START or key <= SEQ_END:
            filtered[key] = content[key]

    #Sort the dict in order of increasing key values
    sorted_data = sorted(filtered.items(), key = operator.itemgetter(0))

    #Write the contents to the file
    for data in sorted_data:
        #print "KEY: " + str(data[0]) + "\nDATA: " + data[1] + "\n"
        f.write(data[1])


#Close the Sockets
sender_socket.close()
receiver_socket.close()
