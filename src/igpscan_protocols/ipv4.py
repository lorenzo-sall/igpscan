#import struct
from struct import *
from socket import *

# ---IP4Packet--------
# stores an IPv4 packet (ignores the options field at the moment)
# --------------------

class IP4Packet:
    # init from raw packet data
    def __init__(self, rawBuffer=None, crafted=False):

        self.userCrafted = crafted

        # unpacked fields (int)
        self.IP4HeaderLen = 0
        self.IP4Version = 0
        self.IP4DiffServ = 0        # this is actually Differentiated Services Code Point (6 bits) and Explicit Congestion Notification (2 bits) 
        self.IP4Length = 0          # already usable
        self.IP4Ident = 0
        self.IP4FlagsAndOffset = 0
        self.IP4Ttl = 0
        self.IP4Proto = 0           # already usable
        self.IP4HeaderChecksum = 0
        self.IP4SrcIp = 0
        self.IP4DstIp = 0

        # human readable
        self.IP4bHeaderLen = 0      # actual header length in bytes (value * 4)
        self.IP4sSrcIp = ''         # dotted source IP
        self.IP4sDstIp = ''         # dotted dest IP

        # payload
        self.IP4Payload = None

        if not self.userCrafted:
            # ! network (big endian), B uchar (1), H ushort (2), I uint (4), Q ulonglong (8)
            IP4header = unpack('!BBHHHBBHII', rawBuffer[0:20])

            self.IP4Version = (IP4header[0] & 0xF0) >> 4
            self.IP4HeaderLen = (IP4header[0] & 0x0F)
            self.IP4DiffServ = IP4header[1]
            self.IP4Length = IP4header[2]
            self.IP4Ident = IP4header[3]
            self.IP4FlagsAndOffset = IP4header[4]
            self.IP4Ttl = IP4header[5]
            self.IP4Proto = IP4header[6]
            self.IP4HeaderChecksum = IP4header[7]
            self.IP4SrcIp = IP4header[8]
            self.IP4DstIp = IP4header[9]

            self.IP4bHeaderLen = self.IP4HeaderLen * 4
            self.IP4sSrcIp = inet_ntoa(pack('!I', self.IP4SrcIp))
            self.IP4sDstIp = inet_ntoa(pack('!I', self.IP4DstIp))

            self.IP4Payload = rawBuffer[self.IP4bHeaderLen:]
        
        else:
            self.IP4Payload = rawBuffer
    
    # print useful packet contents in a human readable format
    def printReadable(self):

        print('[i] IP info:')

        if self.userCrafted:
            print('    User-generated packet.')
        else:
            print(f'    IPv{self.IP4Version} packet from {self.IP4sSrcIp} to {self.IP4sDstIp}')
            print(f'    Protocol: {self.IP4Proto}')
            print(f'    Packet length: {self.IP4Length} bytes')
            print(f'    Header: {self.IP4bHeaderLen} bytes')
            print(f'    Header checksum: {hex(self.IP4HeaderChecksum)} ({self.IP4HeaderChecksum})')

        print(f'    Payload: {len(self.IP4Payload)} bytes')
        print('------ Payload: ------')
        printBytes(self.IP4Payload)
        print('-----------------------')