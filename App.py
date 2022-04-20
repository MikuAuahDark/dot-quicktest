import socket
import ssl
import binascii
import struct
import traceback

HOST, PORT = '1.1.1.1', 853

#
class dnsTLS:
    def __init__(self, host='1dot1dot1dot1.cloudflare-dns.com', port=853, ip=None):
        self.host = host
        self.port = port
        if ip is None:
            self.ips = socket.gethostbyname_ex(host)[2]
        elif isinstance(ip, str):
            self.ips = [ip]
        else:
            self.ips = ip
    def extractIp(self, response):
        """Function will extract IP field from last 8 fields of HEXA ,REF - https://tools.ietf.org/html/rfc1035
           @params - response - DNS Response
           @return - The IP from the DNS Response
         """
        return '.'.join([str(x) for x in response[-4:]])

    def getLength(self, packet):
        """Function will gets the length of DNS TCP Packet for a domain
           @params - packet - DNS Packet
           @return - Packet Length in HEXA format
        """
        l = len(packet) / 2
        h = "{0:x}".format(l)
        diff = 4 - len(h)
        return diff * "0" + h

    def buildPacket(self, url):
        """Function will build a DNS packet as per rfc1035 - Uses struct to  Interpret strings as packed binary data
         @params - the url to query in dns
         @return - DNS PACKET !
         """
        packet = struct.pack(">H", 12049)  # Query Ids (Just 1 for now)
        packet += struct.pack(">H", 256)  # Flags
        packet += struct.pack(">H", 1)  # Questions
        packet += struct.pack(">H", 0)  # Answers
        packet += struct.pack(">H", 0)  # Authorities
        packet += struct.pack(">H", 0)  # Additional
        split_url = url.split(".")
        for part in split_url:
            packet += struct.pack("B", len(part))
            for byte in part.encode('UTF-8'):
                packet += struct.pack("B", byte)
        packet += struct.pack("B", 0)  # End of String
        packet += struct.pack(">H", 1)  # Query Type
        packet += struct.pack(">H", 1)  # Query Class
        return struct.pack(">H", len(packet)) + packet

    def sendMessage(self, message, sock):
        """Function will sends the DNS Packet Message to the DNS Over TLS Provider"""
        sock.send(message)
        data = sock.recv(4096)
        return data

    def connect(self):
        """Function to create SSL session and return it """
        wrappedSocket = None
        # CREATE SOCKET
        for ip in self.ips:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(30)

                context = ssl.create_default_context()
                context = ssl.SSLContext()

                wrappedSocket = context.wrap_socket(sock, server_hostname=self.host)

                # CONNECT AND PRINT REPLY
                wrappedSocket.connect((ip, self.port))
            except Exception as e:
                print(''.join(traceback.format_exception(e)))
        # CLOSE SOCKET CONNECTION
        if wrappedSocket is None:
            raise Exception("Connect failed")
        return wrappedSocket
