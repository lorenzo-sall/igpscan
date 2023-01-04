import argparse
import struct
import socket
from socket import *
from struct import *

# OSPF PACKET TYPES
OSPF_TYPE = {
    1: 'HELLO',
    2: 'DATABASE_DESCRIPTION',
    3: 'LINK_STATE_REQUEST',
    4: 'LINK_STATE_UPDATE',
    5: 'LINK_STATE_ACK'
}

# ROUTER LSA LINK TYPE
ROUTER_LSA_LINK_TYPE = {
    1: 'Point-to-point',
    2: 'Transit',
    3: 'Stub',
    4: 'Virtual link'
}

# EIGRP OPCODES
EIGRP_OPCODE = {
    1: 'EIGRP_OPC_UPDATE',
    2: 'EIGRP_OPC_REQUEST',
    3: 'EIGRP_OPC_QUERY',
    4: 'EIGRP_OPC_REPLY',
    5: 'EIGRP_OPC_HELLO',
    6: 'EIGRP_OPC_IPXSAP',
    7: 'EIGRP_OPC_PROBE',
    8: 'EIGRP_OPC_ACK',
    9: '',
    10: 'EIGRP_OPC_SIAQUERY',
    11: 'EIGRP_OPC_SIAREPLY'
}

# EIGRP TLV PROTOCOL CLASSIFICATION (type field high)

TLV_PROTOCOL_CLASSIFICATION = {
    0x00: 'GENERAL',
    0x01: 'IPv4',
    0x04: 'IPv6',
    0x05: 'SAF',
    0x06: 'MULTIPROTOCOL'
}

# EIGRP GENERIC TLV DEFINITIONS (TLV OPCODE) (type field low)
TLV_GENERIC_DEFINITION = {
    0x01: 'PARAMETER_TYPE',
    0x02: 'AUTHENTICATION_TYPE',
    0x03: 'SEQUENCE_TYPE',
    0x04: 'SOFTWARE_VERSION_TYPE',
    0x05: 'MULTICAST_SEQUENCE_TYPE',
    0x06: 'PEER_INFORMATION_TYPE',
    0x07: 'PEER_TERMINATION_TYPE',
    0x08: 'PEER_TID_LIST_TYPE',
    0xf5: 'TOPOLOGY_ID_LIST'
}

TLV_IPV4_IPV6_DEFINITION = {
    0x02: 'INTERNAL_TYPE',
    0x03: 'EXTERNAL_TYPE',
    0x04: 'COMMUNITY_TYPE'
}

TLV_MULTIPROTOCOL_DEFINITION = {
    0x01: 'REQUEST_TYPE',
    0X02: 'INTERNAL_TYPE',
    0X03: 'EXTERNAL_TYPE'
}

AFI_ENCODING = {
    1: 'IPv4',
    2: 'IPv6',
    16384: 'EIGRP Common Service Family',
    16385: 'EIGRP IPv4 Service Family',
    16386: 'EIGRP IPv6 Service Family'
}

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

# ---OSPFPacket-------
# inherits from IP4Packet, stores an OSPF packet
# RFC 2328 (A.3.1) - Every OSPF packet starts with a standard 24 byte header
# --------------------

class OSPFPacket(IP4Packet):

    # init from raw packet data
    def __init__(self, rawBuffer=None, crafted=False):

        # unpacked fields (int)
        self.OSPFProtoVersion = 0
        self.OSPFPacketType = 0          # 1 Hello, 2 Database Description, 3 Link State Request, 4 Link State Update, 5 Link State Acknowledgment
        self.OSPFLength = 0              # length of packet in bytes, includes header, excludes LLS data block
        self.OSPFRouterId = 0
        self.OSPFAreaId = 0
        self.OSPFChecksum = 0
        self.OSPFAuType = 0              # 0 non-authentication, 1 simple authentication, 2 MD5 authentication
        self.OSPFAuthentication = 0      # 64 bit. TO IMPLEMENT. see appendix D RFC 2328 for details

        # human readable
        self.OSPFsRouterId = ''
        self.OSPFsAreaId = ''
        
        # payload
        self.OSPFPayload = None

        if crafted:
            super().__init__(rawBuffer, crafted=True)
        else:
            super().__init__(rawBuffer, crafted=False)

        try:
            if not self.userCrafted:
                if self.IP4Proto != 89:
                    raise ProtocolMismatch
            
            OSPFheader = unpack('!BBHIIHHQ', self.IP4Payload[0:24])

            self.OSPFProtoVersion = OSPFheader[0]
            self.OSPFPacketType = OSPFheader[1]
            self.OSPFLength = OSPFheader[2]
            self.OSPFRouterId = OSPFheader[3]
            self.OSPFAreaId = OSPFheader[4]
            self.OSPFChecksum = OSPFheader[5]
            self.OSPFAuType = OSPFheader[6]
            self.OSPFAuthentication = OSPFheader[7]

            self.OSPFsRouterId = inet_ntoa(pack('!I', self.OSPFRouterId))
            self.OSPFsAreaId = inet_ntoa(pack('!I', self.OSPFAreaId))

            self.OSPFPayload = self.IP4Payload[24:]

        except ProtocolMismatch:
            print('IP4Proto value does not match the packet class (OSPFPacket).')
            exit(1)
    
    # init from values
    # in this case IP4Packet.userCrafted is set to True and IP4Packet.IP4Payload is initialised, the other fields will be 0
    # this is used to craft OSPF packets and the IP portion will be handled by python
    # this should calculate OSPFLength and OSPFChecksum 
    # (protoVersion, packetType, routerId, areaId, auType, authentication, payload)
    # use @classmethod (https://realpython.com/python-multiple-constructors/)

    @classmethod
    def fromValues(cls, protoVersion, packetType, packetLength, routerId, areaId, auType, authentication, payload):
        
        rawb = b''
        # setting version and type
        rawb += pack('!B', protoVersion)
        rawb += pack('!B', packetType)
        # manually setting length, could be automated
        rawb += pack('!H', packetLength)
        # set router ID and area ID
        rawb += inet_aton(routerId)
        rawb += inet_aton(areaId)
        # initialise checksum to 0
        rawb += pack('!H', 0)
        # set authentication type and clear authentication data as per RFC 2328 A.3.1
        rawb += pack('!H', auType)
        rawb += pack('!Q', 0)
        # append payload
        rawb += payload

        if auType == 0:
            checksum = inetChecksum(rawb)
        elif auType == 1:
            checksum = inetChecksum(rawb)
        elif auType == 2:
            # LEAVE CHECKSUM AT 0 AS PER RFC 2328 D.4.3(2)
            checksum = 0
        else:
            print('[!] OSPF auType field values > 2 are reserved. Functionality not implemented.')
            print('[!] Handling packet as not authenticated. Crafted packet might be invalid.')
            checksum = inetChecksum(rawb)

        # repack with checksum
        rawb = b''
        rawb += pack('!B', protoVersion)
        rawb += pack('!B', packetType)
        rawb += pack('!H', packetLength)
        rawb += inet_aton(routerId)
        rawb += inet_aton(areaId)
        rawb += pack('!H', checksum)

        # repack according to autype
        if auType == 0:
            rawb += pack('!H', auType)
            rawb += pack('!Q', 0)
        elif auType == 1:
            rawb += pack('!H', auType)
            rawb += pack('!Q', authentication)
        elif auType == 2:
            print('[!] Cryptographic authentication not yet implemented. Packet might be invalid.')
            rawb += pack('!H', auType)
            rawb += pack('!Q', authentication)
        else:
            print('[!] OSPF auType field values > 2 are reserved. Functionality not implemented.')
            print('[!] Handling packet as not authenticated. Crafted packet might be invalid.')
            rawb += pack('!H', auType)
            rawb += pack('!Q', 0)
        
        rawb += payload

        return cls(rawb, crafted=True)


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

        print('[i] OSPF info:')
        print(f'    Protocol version {self.OSPFProtoVersion}')
        print(f'    Packet type: {self.OSPFPacketType} ({OSPF_TYPE[self.OSPFPacketType]})')
        print(f'    Packet length: {self.OSPFLength} bytes')
        print(f'    Router ID: {self.OSPFsRouterId}')
        print(f'    Area ID: {self.OSPFsAreaId}')
        print(f'    Auth type: {self.OSPFAuType}')
        print(f'    Auth : NOT YET IMPLEMENTED')    # TO DO
        print(f'    OSPF checksum: {hex(self.OSPFChecksum)}')
        print('------ Payload: ------')
        printBytes(self.OSPFPayload)
        print('-----------------------')

# ---EIGRPPacket-------
# inherits from IP4Packet, stores an EIGRP packet
# RFC 7868
#  6.5. EIGRP Packet Header
#   The basic EIGRP packet payload format is identical for both IPv4 and
#   IPv6, although there are some protocol-specific variations. Packets
#   consist of a header, followed by a set of variable-length fields
#   consisting of Type/Length/Value (TLV) triplets.
# --------------------

class EIGRPPacket(IP4Packet):

    # init from raw packet data
    def __init__(self, rawBuffer=None, crafted=False):
        # unpacked fields (int)
        self.EIGRPHeaderVersion = 0
        self.EIGRPOpCode = 0          # RFC 7868 page 49
        self.EIGRPChecksum = 0
        self.EIGRPFlags = 0
        self.EIGRPSeqNum = 0
        self.EIGRPAckNum = 0
        self.EIGRPVirtualRID = 0
        self.EIGRPAutonomousSysNum = 0
        # human readable
        # ...
        # payload
        self.EIGRPPayload = None
        # extracted TLV fields
        self.EIGRPTLVs = []

        if crafted:
            super().__init__(rawBuffer, crafted=True)
        else:
            super().__init__(rawBuffer, crafted=False)

        try:
            if not self.userCrafted:
                if self.IP4Proto != 88:
                    raise ProtocolMismatch
            
            EIGRPheader = unpack('!BBHIIIHH', self.IP4Payload[0:20])

            self.EIGRPHeaderVersion = EIGRPheader[0]
            self.EIGRPOpCode = EIGRPheader[1]
            self.EIGRPChecksum = EIGRPheader[2]
            self.EIGRPFlags = EIGRPheader[3]
            self.EIGRPSeqNum = EIGRPheader[4]
            self.EIGRPAckNum = EIGRPheader[5]
            self.EIGRPVirtualRID = EIGRPheader[6]
            self.EIGRPAutonomousSysNum = EIGRPheader[7]

            self.EIGRPPayload = self.IP4Payload[20:]

            rawtlvs = self.EIGRPPayload

            while len(rawtlvs) > 0:
                tlvheader = unpack('!BBH', rawtlvs[:4])
                typeh = tlvheader[0]
                typel = tlvheader[1]
                tlvlength = tlvheader[2]
                tlv = rawtlvs[:tlvlength]
                rawtlvs = rawtlvs[tlvlength:]
                self.EIGRPTLVs.append(EIGRPTLV(typeh, typel, tlvlength, tlv[4:]))
                if len(rawtlvs) < 4:
                    break

        except ProtocolMismatch:
            print('IP4Proto value does not match the packet class (EIGRPPacket).')
            exit(1)

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

        print('[i] EIGRP info:')
        print(f'    Header format version: {self.EIGRPHeaderVersion}')
        print(f'    OpCode: {self.EIGRPOpCode} ({EIGRP_OPCODE[self.EIGRPOpCode]})')
        print(f'    EIGRP checksum: {hex(self.EIGRPChecksum)}')
        print(f'    Flags: {self.EIGRPFlags}')
        print(f'    Sequence number: {self.EIGRPSeqNum}')
        print(f'    Acknowledgement number: {self.EIGRPAckNum}')
        print(f'    Virtual router ID: {self.EIGRPVirtualRID}')
        print(f'    AS number: {self.EIGRPAutonomousSysNum}')
        print('------ Payload: ------')
        printBytes(self.EIGRPPayload)
        print('-----------------------')

        # print TLVs
        print(f'    TLV content:')
        for t in self.EIGRPTLVs:
            print(f'      TLV #{self.EIGRPTLVs.index(t) + 1}')
            try:
                print(f'        Classification: {TLV_PROTOCOL_CLASSIFICATION[t.EIGRPTLVTypeHigh]} (0x{t.EIGRPTLVTypeHigh:02x})')
            except:
                print(f'        Classification: unknown (0x{t.EIGRPTLVTypeHigh:02x})')
            if t.EIGRPTLVTypeHigh == 0x00:
                try:
                    print(f'        Opcode: {TLV_GENERIC_DEFINITION[t.EIGRPTLVTypeLow]} (0x{t.EIGRPTLVTypeLow:02x})')
                except:
                    print(f'        Opcode: unknown (0x{t.EIGRPTLVTypeLow:02x})')
            elif t.EIGRPTLVTypeHigh == 0x01:
                try:
                    print(f'        Opcode: {TLV_IPV4_IPV6_DEFINITION[t.EIGRPTLVTypeLow]} (0x{t.EIGRPTLVTypeLow:02x})')
                except:
                    print(f'        Opcode: unknown (0x{t.EIGRPTLVTypeLow:02x})')
            elif t.EIGRPTLVTypeHigh == 0x04:
                try:
                    print(f'        Opcode: {TLV_IPV4_IPV6_DEFINITION[t.EIGRPTLVTypeLow]} (0x{t.EIGRPTLVTypeLow:02x})')
                except:
                    print(f'        Opcode: unknown (0x{t.EIGRPTLVTypeLow:02x})')
            elif t.EIGRPTLVTypeHigh == 0x06:
                try:
                    print(f'        Opcode: {TLV_MULTIPROTOCOL_DEFINITION[t.EIGRPTLVTypeLow]} (0x{t.EIGRPTLVTypeLow:02x})')
                except:
                    print(f'        Opcode: unknown (0x{t.EIGRPTLVTypeLow:02x})')

            print(f'        Length: {t.EIGRPTLVLen}')
            print(f'        Value:')
            printBytes(t.EIGRPTLVRawValue)

    # init from values
    @classmethod
    def fromValues(cls, headerVersion, opCode, flags, seqNum, ackNum, virtualRID, asNum, payload):
        rawb = b''
        rawb += pack('!B', headerVersion)
        rawb += pack('!B', opCode)
        rawb += pack('!H', 0)   # initialize checksum to 0
        rawb += pack('!I', flags)
        rawb += pack('!I', seqNum)
        rawb += pack('!I', ackNum)
        rawb += pack('!H', virtualRID)
        rawb += pack('!H', asNum)
        rawb += payload

        checksum = inetChecksum(rawb)

        rawb = b''
        rawb += pack('!B', headerVersion)
        rawb += pack('!B', opCode)
        rawb += pack('!H', checksum)   # initialize checksum to 0
        rawb += pack('!I', flags)
        rawb += pack('!I', seqNum)
        rawb += pack('!I', ackNum)
        rawb += pack('!H', virtualRID)
        rawb += pack('!H', asNum)
        rawb += payload

        return cls(rawb, crafted=True)


# this class describes an OSPF LSA, initialised by the header received in DB Description packets.
# the LSA data is stored when received in the LSAdata array 
class OSPFLSA:

    def __init__(self, rawLSA):

        self.rawLSAHeader = b''
        self.rawLSAData = b''

        # header fields
        self.LSAge = 0
        self.options = 0
        self.LSType = 0      # (1) Router-LSA, (2) Network-LSA, (3) Summary-LSA IP network, (4) Summary-LSA ASBR, (5) AS-external-LSA
        self.linkStateID = 0
        self.advertisingRouter = 0
        self.sequenceNum = 0
        self.checksum = 0
        self.length = 0

        # LS Update data
        #flags = 0
        #linkCount = 0
        #LSAdata = []

        self.rawLSAHeader = rawLSA[0:20] # store the raw header
        if len(rawLSA) > 20:
            self.rawLSAData = rawLSA[20:] # store raw LSA data if present
        
        LSAHeader = unpack('!HBBIIIHH', rawLSA[0:20])
        self.LSAge = LSAHeader[0]
        self.options = LSAHeader[1]
        self.LSType = LSAHeader[2]
        self.linkStateID = LSAHeader[3]
        self.advertisingRouter = LSAHeader[4]
        self.sequenceNum = LSAHeader[5]
        self.checksum = LSAHeader[6]
        self.length = LSAHeader[7]
    
    def exportRequest(self):
        req = b''
        req += pack('!I', self.LSType)
        req += pack('!I', self.linkStateID)
        req += pack('!I', self.advertisingRouter)

        return req

# this class represent the TLV (type, length, value) portion of an EIGRP packet 
class EIGRPTLV:
    def __init__(self, th, tl, l, v):
        self.EIGRPTLVTypeHigh = th
        self.EIGRPTLVTypeLow = tl
        self.EIGRPTLVLen = l
        self.EIGRPTLVRawValue = v

class Error(Exception):
    """Base class for user defined exceptions"""
    pass

class ProtocolMismatch(Error):
    """Raised when tryng to create a child class of IP4Packet from a packet with a protocol value not matching the child class.
    EIGRP protocol = 88
    OSPF protocol = 89
    """
    pass

class OSPFAuthenticationError(Error):
    """Raised if an OSPF packet uses an authentication mechanism that is not implemented here.
    """

# get our own IPv4 address
# needed to filter certain packets
# source: https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
# REFERENCE THIS
def get_ip():
    s = socket(AF_INET, SOCK_DGRAM)
    s.settimeout(0)
    try:
        # doesn't even have to be reachable
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

# prints a sequence of bytes in a readable fashion.
# arguments:
#   raw (bytes) - the bytes to print
#   perLine (int) - number of bytes per line
#   printHeaders (bool) - option to print headers and line numbers
def printBytes(raw, perLine=16, printHeaders=True):
    passes = len(raw) // perLine

    # print header like '        	00                   07-08                   15 '
    if printHeaders:
        print(' '*8 + ' '*3, end='')
        for i in range(0, perLine):
            if i == 0:
                print(f'{i:02}', end=' ')
            elif (i % 8) == 0:
                print(f'{i:02}', end=' ')
            elif (i % 8) == 7:
                if i == (perLine - 1):
                    print(f'{i:02}', end=' ')
                else:
                    print(f'{i:02}', end='-')
            else:
                print('  ', end=' ')
        print('')


    c = 0
    while c < passes:
        if printHeaders:
            print(f'{c*perLine:08}   ',end='') #print left column (in decimal, byte count)
        print(' '.join(f'{b:02x}' for b in raw[c * perLine : (c + 1) * perLine]))
        c = c + 1
    if printHeaders:
        print(f'{c*perLine:08}   ',end='') #print left column (in decimal, byte count)
    print(' '.join(f'{b:02x}' for b in raw[c * perLine :]))

# RFC 2338 describes how to compute the checksum field of OSPF packets.
# RFC 1071 describes how to compute the internet checksum.
def inetChecksum(rawb):

    # if the buffer length is not an integral number of 16-bit words pad with 0x00
    if len(rawb) % 2 == 1:
        rawb += b'\x00'

    # build an array of 16-bit words
    a = []
    for i in range(0, len(rawb), 2):
        a.append(rawb[i:i+2])

    # convert to array of integers (big endian, unsigned) and sum each member
    b = []
    for x in a:
        b.append(int.from_bytes(x, byteorder='big', signed=False))
    
    sum_no_carry = 0
    for x in b:
        sum_no_carry += x
    
    # NEEDS TO BE RECURSIVE
    carry_around = (sum_no_carry & 0xffff) + (sum_no_carry >> 16)
    complement = ~carry_around & 0xFFFF

    return complement

# OSPF LSA parsing to extract information (LSA fromat in RFC 2328 A.4)
def parseLSA(a, l):
    if l.LSType == 1:
        print(f'[i] Router-LSA ({l.checksum})')
        print(f'    Area ID: {a}')
        print(f'    Link State ID: {inet_ntoa(pack("!I", l.linkStateID))}')
        print(f'    Advertising Router: {inet_ntoa(pack("!I", l.advertisingRouter))}')
        ld = l.rawLSAData
        routerLSAFlags = ld[:2]     # this gives some info on the router role (00000VEB 00000000)
        linkNumber = unpack('!H', ld[2:4])[0]     # number of links
        ld = ld[4:]
        linkCounter = 0
        while linkCounter < linkNumber:
            linkID = ld[:4]
            linkData = ld[4:8]
            linkType = unpack('!B', ld[8:9])[0]
            metricNumber = unpack('!B', ld[9:10])[0]
            defaultMetric = unpack('!H', ld[10:12])[0]
            ld = ld[12:]  # strip the information already processed
            if metricNumber > 0:    # https://datatracker.ietf.org/doc/html/rfc1583#page-186
                c = 0
                addictionalMetrics = []
                while c < metricNumber:
                    addictionalMetrics.append(ld[:4])    # format: TOS(1 byte) + NULL(1 byte) + METRIC(2 bytes). not processed at this time
                    ld = ld[:4]
                    c = c + 1
            print(f'    Link #{linkCounter+1}:')
            print(f'      Link ID: {inet_ntoa(linkID)}\n      Link Data: {inet_ntoa(linkData)}\n      Link Type: {ROUTER_LSA_LINK_TYPE[linkType]}\n      Metric: {defaultMetric}')
            linkCounter = linkCounter + 1
        print()

    if l.LSType == 2:
        print(f'[i] Network-LSA ({l.checksum})')
        print(f'    Area ID: {a}')
        print(f'    Link State ID: {inet_ntoa(pack("!I", l.linkStateID))}')
        print(f'    Advertising Router: {inet_ntoa(pack("!I", l.advertisingRouter))}')
        ld = l.rawLSAData
        networkMask = ld[:4]
        print(f'      Network mask: {inet_ntoa(networkMask)}')
        print('      Attached routers:')
        ld = ld[4:]
        n = len(ld) / 4 # each attached router id is stored in 4 bytes
        c = 0
        while c < n:
            ar = ld[:4]
            print(f'        {inet_ntoa(ar)}')
            ld = ld[4:]
            c = c + 1 
    if l.LSType == 3:
        print(f'{l.checksum}\t\t-> Summary-LSA (IP network)') # not yet parsed
    if l.LSType == 4:
        print(f'{l.checksum}\t\t-> Summary-LSA (ASBR)') # not yet parsed
    if l.LSType == 5:
        print(f'{l.checksum}\t\t-> AS-External-LSA') # not yet parsed

def parseRouteTLV(t):
    
    if t.EIGRPTLVTypeHigh == 0x01:
        pass

    elif t.EIGRPTLVTypeHigh == 0x04:
        pass

    elif t.EIGRPTLVTypeHigh == 0x06:

        if t.EIGRPTLVTypeLow == 0x01:
            print('\n[i] Multiprotocol TLV: REQUEST')

        elif t.EIGRPTLVTypeLow == 0x02:
            print('\n[i] Multiprotocol TLV: INTERNAL')
            v = t.EIGRPTLVRawValue
            ids = unpack('!HHI', v[:8])
            tid = ids[0]    # topology id
            afi = ids[1]    # address family id
            rid = ids[2]    # router id
            print(f"    Router ID: {inet_ntoa(pack('!I', rid))}")
            print(f'    Topology: {tid}')
            print(f'    Address family: {AFI_ENCODING[afi]}')
            v = v[8:]

            offset = unpack('!B', v[:1])[0]
            wideMetric = v[:24+offset]  # not processed atm
            v = v[24+offset:]
            # destination descriptor
            nhop = inet_ntoa(v[:4])    # not documented in RFC ???
            print(f'    Next hop: {nhop}')
            v = v[4:]
            mask = unpack('!B', v[:1])[0]
            dest = v[1:]
            while len(dest) < 4:
                dest += b'\x00'
            print(f'    Destination: {inet_ntoa(dest)}/{mask}')

        elif t.EIGRPTLVTypeLow == 0x03:
            print('\n[i] Multiprotocol TLV: EXTERNAL')
        else:
            pass

    else:
        pass

# INITIALISATION

OSPF_ALL_MCAST_GROUP = '224.0.0.5'  # "all OSPF routers" multicast group
OSPF_PROTO_N = 89
EIGRP_ALL_MCAST_GROUP = '224.0.0.10'   # EIGRP routers multicast group
EIGRP_PROTO_N = 88

ownIPv4Addr = get_ip()

toolDescription = '''
    ______________                      
   /  _/ ____/ __ \______________  ____ 
   / // / __/ /_/ / ___/ ___/ __ `/ __ \\
 _/ // /_/ / ____(__  ) /__/ /_/ / / / /
/___/\____/_/   /____/\___/\__,_/_/ /_/ 
                                        
Version 0.1
This section can contain a disclaimer.
'''

usageExamples = '''
Here we have some examples. This is printed after the help.
$ sudo asd.py -a asd -b 2 -c asd.out
$ sudo asd.py -a asd -b 20 -c asd.out -v -x
$ sudo asd.py -a fgh -c -
'''

parser = argparse.ArgumentParser(description=toolDescription, epilog=usageExamples, formatter_class=argparse.RawDescriptionHelpFormatter)
subparsers = parser.add_subparsers(title='Protocol', dest='protocol', description='Supported protocols', help='Select the protocol')
subparsers.required = True
parserOSPF = subparsers.add_parser('ospf')
parserEIGRP = subparsers.add_parser('eigrp')

parserOSPF.add_argument('-i', '--id', default='254.254.254.254', help='Set the OSPF Router-Id')
parserEIGRP.add_argument('-t', '--target', default='0.0.0.0', help='Set the EIGRP target router address (X.X.X.X)')
parserEIGRP.add_argument('-d', '--point-to-point', action='store_true', default=False, help='Set point-to-point mode for EIGRP scans')
parser.add_argument('-m', '--mode', required=True, choices=['passive', 'active', 'inject'], help='Mode of operation')
parser.add_argument('-v', '--verbose', default=False, action='store_true', help='Increase output verbosity. Must be specified before the mode')
parser.add_argument('-o', '--output', default=False, action='store_true', help='Try to write a log file in the current directory')
parser.add_argument('-s', '--seconds-time-out', type=int, default=20, help='Scanning sockets will time out after N seconds')
parser.add_argument('-k', '--keep-alive', action='store_true', help='Continue interaction with neighbors, if possible')
parser.add_argument('-x', '--max-captures', type=int, default=1, help='Set the maximum number of captures for passive scans and active initialization')
parser.add_argument('-q', '--quiet', default=False, action='store_true', help='Disable prompts for user input. Useful if a full terminal is not available')

args = vars(parser.parse_args())
### DEBUG - argumets override
#args = {'protocol': 'eigrp', 'mode': 'active', 'verbose': False, 'output': False, 'seconds_time_out': 20, 'keep_alive': False, 'target': '192.168.5.1', 'full_terminal': False, 'point_to_point': True, 'max_captures': 10}
#args = {'protocol': 'ospf', 'mode': 'passive', 'verbose': False, 'output': False, 'seconds_time_out': 20, 'keep_alive': False, 'max_captures': 10, 'full_terminal': False, 'id': '254.254.254.254'}

if args['protocol'] == 'eigrp':
    if args['mode'] == 'active':
        if args['target'] == '0.0.0.0':
            print('[X] Active EIGRP scans require a target host: -t/--target. Terminating...')
            exit(1)

# print results of passive scan
def printPassiveResults(hostList):
    if args['protocol'] == 'ospf':
        print('\n[i] Passive OSPF scan results')
        print('    Seen OSPF hosts:')
    elif args['protocol'] == 'eigrp':
        print('\n[i] Passive EIGRP scan results')
        print('    Seen EIGRP hosts:')
    for h in hostList:
        print(f'      {h}')

# print settings and prompt
def printSettings():
    print(f'[i] Starting {args["mode"]} {args["protocol"]} scan')
    print('    General settings:')
    print(f'      IP address: {ownIPv4Addr}')
    print(f'      Verbose: {args["verbose"]}')
    print(f'      Timeout: {args["seconds_time_out"]} seconds')
    print(f'      Max captures: {args["max_captures"]}')
    print(f'      Full terminal: {not args["quiet"]}')
    print(f'      Keep alive: {args["keep_alive"]} (NOT YET IMPLEMENTED)')
    print(f'      Output: {args["output"]} (NOT YET IMPLEMENTED)')

    if args['protocol'] == 'ospf':
        print('    OSPF settings:')
        print(f'      Router ID: {args["id"]}')
    if args['protocol'] == 'eigrp':
        print('    EIGRP settings:')
        print(f'      Target: {args["target"]} (not affecting passive scans)')
        print(f'      Point-to-point: {args["point_to_point"]}')
    
    if not args['quiet']:
        try:
            input('\n[?] Press a key to start scan, CTRL-C to exit.')
        except KeyboardInterrupt:
            print('\n[X] Terminating...')
            exit(1)

printSettings()

#### OSPF
if args['protocol'] == 'ospf':
    if args['mode'] == 'active':
        print(f'[i] Started {args["mode"]} {args["protocol"]} scan')
        areas = []

        c = 0
        while c < args['max_captures']:

            try:
                s = socket(AF_INET, SOCK_RAW, OSPF_PROTO_N)
                mcast = struct.pack('=4sl', inet_aton(OSPF_ALL_MCAST_GROUP), INADDR_ANY)
                s.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, mcast)
                s.settimeout(args['seconds_time_out'])

                data, addr = s.recvfrom(1024)
                p = OSPFPacket(data)
                
                if p.OSPFPacketType != 1:   # HELLO
                    s.setsockopt(IPPROTO_IP, IP_DROP_MEMBERSHIP, mcast) # leave multicast group
                    s.close()
                    continue
                
                if p.OSPFAuType > 1:
                    raise OSPFAuthenticationError
                
                area = p.OSPFAreaId
                knownArea = False
                for a in areas:             # check if area is already recorded
                    if area == a[0]:
                        knownArea = True

                if not knownArea:
                    auType = p.OSPFAuType
                    auData = p.OSPFAuthentication

                    helloData = unpack('!IHBBIII', p.OSPFPayload[0:20]) # hello packet data excluding neighboring routers
                    helloInterval = helloData[1]
                    deadInterval = helloData[4]
                    designatedRouter = helloData[5]
                    backupDRouter = helloData[6]

                    areas.append((area, auType, auData, helloInterval, deadInterval, inet_ntoa(pack('!I', designatedRouter)), inet_ntoa(pack('!I', backupDRouter))))

                c = c + 1
                s.close()

            except timeout:
                s.setsockopt(IPPROTO_IP, IP_DROP_MEMBERSHIP, mcast)
                s.close()
                c = c + 1
                continue

            except OSPFAuthenticationError:
                print(f'[!] Ignoring OSPF packet: authentication type not supported (autype = {p.OSPFAuType})')
                s.setsockopt(IPPROTO_IP, IP_DROP_MEMBERSHIP, mcast)
                s.close()
                continue
        
        print(f'\n[i] OSPF Area information:')
        for a in areas:
            print(f'    Area {a[0]}')
            print(f'      Hello interval: {a[3]}')
            print(f'      Dead interval: {a[4]}')
            print(f'      Designated router: {a[5]}')
            print(f'      Backup: {a[6]}')

        # attempt adjacency in each area
        routes = [] # stores tuples (area, lsaArray)
        for a in areas:
            print(f'\n[i] Attempting adjacency in Area {a[0]}\n')
            drIP = a[5]
            s = socket(AF_INET, SOCK_RAW, OSPF_PROTO_N)
            mcast = struct.pack('=4sl', inet_aton(OSPF_ALL_MCAST_GROUP), INADDR_ANY)
            s.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, mcast)

            # 1. RECEIVE MULTICAST HELLO FROM (DESIGNATED) ROUTER
            while True:
                data, addr = s.recvfrom(1024)
                if addr[0] != ownIPv4Addr:
                    p = OSPFPacket(data)
                    if p.OSPFAreaId == a[0]:
                        if p.OSPFPacketType == 1:
                            print(f'[<] Received OSPF packet from {addr[0]} ({OSPF_TYPE[p.OSPFPacketType]})')
                            if addr[0] == drIP:
                                if args['verbose']:
                                    p.printReadable()
                                break

            # quick way to extract the optional LLS data block if present (RFC 5613 https://www.rfc-editor.org/rfc/rfc5613.html)
            # this block does not count towards the ospf packet length and is appendend at the end of the packet
            # options are also extracted from the HELLO packet for quick packet manipulation in the next step (OSPFOptions = receivedPayload[2])
            optionaLLSDataBlock = p.IP4Payload[p.OSPFLength:]

            # 2. SEND MULTICAST HELLO (TARTGET DESIGNATED ROUTER)
            rid = args['id']
            area_id = inet_ntoa(pack('!I', a[0]))

            payload = b''
            receivedPayload = unpack('!IHBBIII', p.OSPFPayload[0:20]) # hello packet data excluding neighboring routers
            payload += pack('!I', receivedPayload[0])   # network mask
            payload += pack('!H', receivedPayload[1])   # hello int
            payload += pack('!B', receivedPayload[2])   # options
            payload += pack('!B', 0)                    # set router priority to 0
            payload += pack('!I', receivedPayload[4])   # dead int
            payload += pack('!I', receivedPayload[5])   # dr
            payload += pack('!I', receivedPayload[6])   # bdr
            payload_tail = p.OSPFPayload[20:]           # trailing parts of the hello packet (neiboring routers and LLS data block)

            OSPFOptions = receivedPayload[2]

            tmp_len = p.OSPFLength

            q = OSPFPacket.fromValues(2, 1, p.OSPFLength, rid, area_id, a[1], a[2], payload + payload_tail)
            print(f'[>] Sending OSPF packet to {OSPF_ALL_MCAST_GROUP} ({OSPF_TYPE[q.OSPFPacketType]})')
            s.sendto(q.IP4Payload, (OSPF_ALL_MCAST_GROUP, 0))

            # 3. RECEIVE HELLO FROM ROUTER WITH ACTIVE NEIGHBOR VALUE
            while True:
                data, addr = s.recvfrom(1024)
                if addr[0] != ownIPv4Addr:
                    p = OSPFPacket(data)
                    if p.OSPFAreaId == a[0]:
                        if p.OSPFPacketType == 1:
                            print(f'[<] Received OSPF packet from {addr[0]} ({OSPF_TYPE[p.OSPFPacketType]})')
                            if addr[0] == drIP:
                                if args['verbose']:
                                    p.printReadable()
                                break

            p = OSPFPacket(data)

            # 4. SEND HELLO TO ROUTER WITH ACTIVE NEIGHBOR
            # reusing previous received packet, appending active neighbor and increasing length by 4
            payload += pack('!I', p.OSPFRouterId)       # add router to the active neighbor list

            q = OSPFPacket.fromValues(2, 1, tmp_len + 4, rid, area_id, a[1], a[2], payload + payload_tail)

            print(f'[>] Sending OSPF packet to {addr[0]} ({OSPF_TYPE[q.OSPFPacketType]})')
            s.sendto(q.IP4Payload, (addr[0], 0))

            # 5. RECEIVE DB DESC (INIT, MORE, MASTER)
            while True:
                data, addr = s.recvfrom(1024)
                if addr[0] != ownIPv4Addr:
                    p = OSPFPacket(data)
                    if p.OSPFAreaId == a[0]:
                        if addr[0] == drIP:
                            break
            
            # set check for received DBD
            dbdReceived = False
            if p.OSPFPacketType == 2:
                dbdReceived = True
            
            print(f'[<] Received OSPF packet from {addr[0]} ({OSPF_TYPE[p.OSPFPacketType]})')
            if args['verbose']:
                p.printReadable()

            # 6. SEND DB DESC (INIT, MORE, MASTER)
            # initialise DD sequence (value not important)
            dds = 1000
            ddsb = pack('!I', dds)

            interfaceMTU = b'\x05\xdc'  # 1500
            dbdOptions = b'\x07'        # INIT, MORE, MASTER (0b0111 - 0x07)
            OSPFDBDescription = interfaceMTU + pack('!B', OSPFOptions) + dbdOptions + ddsb
            payload = OSPFDBDescription + optionaLLSDataBlock

            q = OSPFPacket.fromValues(2, 2, 32, rid, area_id, a[1], a[2], payload)

            print(f'[>] Sending OSPF packet to {addr[0]} ({OSPF_TYPE[q.OSPFPacketType]})')
            s.sendto(q.IP4Payload, (addr[0], 0))

            # 6a. RECEIVE DB DESC (INIT, MORE, MASTER)
            if not dbdReceived:
                while True:
                    data, addr = s.recvfrom(1024)
                    if addr[0] != ownIPv4Addr:
                        p = OSPFPacket(data)
                        if p.OSPFAreaId == a[0]:
                            if addr[0] == drIP:
                                if p.OSPFPacketType == 2:
                                    break

                print(f'[<] Received OSPF packet from {addr[0]} ({OSPF_TYPE[p.OSPFPacketType]})')
                if args['verbose']:
                    p.printReadable()

            # 7. RECEIVE DB DESC (MORE) AND EXTRACT LSAs
            while True:
                data, addr = s.recvfrom(1024)
                if addr[0] != ownIPv4Addr:
                    p = OSPFPacket(data)
                    if p.OSPFAreaId == a[0]:
                        if addr[0] == drIP:
                            if p.OSPFPacketType == 2:
                                break
            
            print(f'[<] Received OSPF packet from {addr[0]} ({OSPF_TYPE[p.OSPFPacketType]})')
            if args['verbose']:
                p.printReadable()

            # parse payload to extract LSAs
            # slice the payload using the OSPF packet length field (it does not include the LLS data block)
            # remove the ospf header (24 bytes), the OSPF DB DESCRIPTION header (8 bytes) and the LLS data block from the IP payload
            # each LSA header is 20 bytes.

            rawLSAs = p.IP4Payload[32:p.OSPFLength]
            requestBuffer = b''
            i = 0
            while i < len(rawLSAs):
                l = OSPFLSA(rawLSAs[i:i+20])
                requestBuffer += l.exportRequest()
                i = i + 20

            # 8. SEND DB DESC (MASTER) AND DD SEQUENCE +1
            # this effectively stops the exchange of DBD packets and a DBD(SLAVE) is received
            # a better implementation would be to keep sending DBD(MORE, MASTER) until a DBD(SLAVE) is received
            # then send a DBD(MASTER) and receive a last DBD(SLAVE). This would ensure that, if the information was
            # transmitted in multiple packets, we would receive everything
            dds = dds + 1
            ddsb = pack('!I', dds)

            dbdOptions = b'\x03'        # MASTER (0b0001 - 0x01)
            OSPFDBDescription = interfaceMTU + pack('!B', OSPFOptions) + dbdOptions + ddsb
            payload = OSPFDBDescription + optionaLLSDataBlock

            q = OSPFPacket.fromValues(2, 2, 32, rid, area_id, a[1], a[2], payload)

            print(f'[>] Sending OSPF packet to {addr[0]} ({OSPF_TYPE[q.OSPFPacketType]})')
            s.sendto(q.IP4Payload, (addr[0], 0))

            # 9. RECEIVE DB DESC (SLAVE) AND DD SEQUENCE + 1
            while True:
                data, addr = s.recvfrom(1024)
                if addr[0] != ownIPv4Addr:
                    p = OSPFPacket(data)
                    if p.OSPFAreaId == a[0]:
                        if addr[0] == drIP:
                            if p.OSPFPacketType == 2:
                                break
            
            print(f'[<] Received OSPF packet from {addr[0]} ({OSPF_TYPE[p.OSPFPacketType]})')
            if args['verbose']:
                p.printReadable()

            # 10. SEND LS REQUEST
            payload = requestBuffer #buffer built in section 7

            # type set to 3, len = OSPF header (24) + payload length (no LLS data block in this packet)
            # 12 bytes for each link state request (type (4 bytes), link state ID (4 bytes), advertising router (4 bytes))
            q = OSPFPacket.fromValues(2, 3, 24+len(payload), rid, '0.0.0.0', 0, 0, payload)

            print(f'[>] Sending OSPF packet to {addr[0]} ({OSPF_TYPE[q.OSPFPacketType]})')
            s.sendto(q.IP4Payload, (addr[0], 0))

            # 11. RECEIVE LS UPDATE
            while True:
                data, addr = s.recvfrom(1024)
                if addr[0] != ownIPv4Addr:
                    p = OSPFPacket(data)
                    if p.OSPFAreaId == a[0]:
                        if addr[0] == drIP:
                            if p.OSPFPacketType == 4:
                                break
            
            print(f'[<] Received OSPF packet from {addr[0]} ({OSPF_TYPE[p.OSPFPacketType]})')
            if args['verbose']:
                p.printReadable()

            # 12. PARSE LSU DATA TO EXTRACT LSAs
            lsudata = p.OSPFPayload
            
            # get number of LSAs
            lsaNum = unpack('!I', lsudata[0:4])[0]

            # strip first 4 bytes (the # of LSAs)
            lsudata = lsudata[4:]

            lsaArray = []
            c = 0
            while c < lsaNum:
                header = OSPFLSA(lsudata[0:20])     # take header and store it
                lsaLen = header.length              # get length from header
                lsa = OSPFLSA(lsudata[0:lsaLen])    # create the complete LSA from raw buffer
                lsaArray.append(lsa)                # append LSA to array
                lsudata = lsudata[lsaLen:]          # remove processed data from raw buffer
                c = c + 1

                if args['verbose']:
                    print(f'\n[i] LSA #{c}')
                    printBytes(lsa.rawLSAHeader)
                    printBytes(lsa.rawLSAData)
            
            print('')
            routes.append((a[0], lsaArray))            
            
            '''
            # 13. SEND LS ACKNOWLEDGMENT
            payload = requestBuffer #buffer built in section 7

            q = OSPFPacket.fromValues(2, 5, 24+len(payload), rid, '0.0.0.0', 0, 0, payload)

            print(f'[>] Sending OSPF packet to {addr[0]} ({OSPF_TYPE[q.OSPFPacketType]})')
            #mcast1 = struct.pack('=4sl', inet_aton('224.0.0.6'), INADDR_ANY)
            #s.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, mcast1)
            s.sendto(q.IP4Payload, ('224.0.0.6', 0))
            '''
        # print LSA information for each area
        for a in routes:
            for l in a[1]:
                parseLSA(a[0], l)

    if args['mode'] == 'passive':
        print(f'[i] Started {args["mode"]} {args["protocol"]} scan')
        seenRouters = []
        print('[ ] Listening for incoming OSPF HELLOs...')

        s = socket(AF_INET, SOCK_RAW, OSPF_PROTO_N)
        mcast = struct.pack('=4sl', inet_aton(OSPF_ALL_MCAST_GROUP), INADDR_ANY)
        s.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, mcast)
        s.settimeout(args['seconds_time_out'])

        try:
            c = 0
            while c < args['max_captures']:
                data, addr = s.recvfrom(1024)
                p = IP4Packet(data)
                if p.IP4Proto == 89:
                    print(f'[<] Received OSPF packet from {addr[0]}')
                    if addr[0] not in seenRouters:
                        seenRouters.append(addr[0])
                    if args['verbose']:
                        p = OSPFPacket(data)
                        p.printReadable()
                else:
                    print(f'[<] Received packet from {addr[0]} (protocol: {p.IP4Proto})')
                    if args['verbose']:
                        p.printReadable()
                c = c + 1
        except timeout:
            print('[X] Socket timeout. Terminating...')
            s.setsockopt(IPPROTO_IP, IP_DROP_MEMBERSHIP, mcast) # leave multicast group
            s.close()
            printPassiveResults(seenRouters)
            exit(1)
        except KeyboardInterrupt:
            s.setsockopt(IPPROTO_IP, IP_DROP_MEMBERSHIP, mcast) # leave multicast group
            s.close()
            printPassiveResults(seenRouters)
            exit(1)
        
        printPassiveResults(seenRouters)

    if args['mode'] == 'inject':
        print('[X] Injection mode is not yet implemented')
        pass

#### EIGRP
if args['protocol'] == 'eigrp':
    if args['mode'] == 'active':
        print(f'[i] Started {args["mode"]} {args["protocol"]} scan')

        # create socket and join multicast group
        s = socket(AF_INET, SOCK_RAW, EIGRP_PROTO_N)
        mcast = struct.pack('=4sl', inet_aton(EIGRP_ALL_MCAST_GROUP), INADDR_ANY)
        s.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, mcast)
        s.settimeout(args['seconds_time_out'])

        # filter for route TLVs
        routeTypes = [ 0x0102, 0x0103, 0x0104, 0x0402, 0x0403, 0x0404, 0x0601, 0x0602, 0x0603]
        # route TLVs buffer
        routeTLVs = []
        # set our (arbitrary) sequence number
        seqnum = 13

        # 1. RECEIVE BROADCAST HELLO
        data, addr = s.recvfrom(1024)
        print(f'[<] Received EIGRP packet from {addr[0]}')
        p = EIGRPPacket(data)
        if args['verbose']:
            p.printReadable()

        # 2. COPY PARAMETER_TYPE AND SOFTWARE_VERSION_TYPE (ALSO AUTHENTICATION SHOULD BE HANDLED HERE) TO CRAFT PAYLOAD FOR BROADCAST HELLO
        #    AT THE MOMENT SEEMS REASONABLE TO JUST COPY THE WHOLE PAYLOAD OF THE HELLO PACKET
        '''
        for t in p.EIGRPTLVs:
            if t.EIGRPTLVTypeLow == 0x01:
                print('found parameter')
            if t.EIGRPTLVTypeLow == 0x02:
                print('found authentication')
            if t.EIGRPTLVTypeLow == 0x04:
                print('found version')
        '''

        payload = p.EIGRPPayload

        # 3. SEND BROADCAST HELLO
        # headerVersion, opCode, flags, seqNum, ackNum, virtualRID, asNum, payload
        q = EIGRPPacket.fromValues(p.EIGRPHeaderVersion, 5, p.EIGRPFlags, 0, 0, 0, p.EIGRPAutonomousSysNum, payload)
        print(f'[>] Sending EIGRP packet to {EIGRP_ALL_MCAST_GROUP}')
        s.sendto(q.IP4Payload, (EIGRP_ALL_MCAST_GROUP, 0))    

        # 4. RECEIVE NULL UPDATE (INIT FLAG SET)
        while True:
            data, addr = s.recvfrom(1024)
            if addr[0] != ownIPv4Addr:
                p = EIGRPPacket(data)
                if p.IP4sDstIp != '224.0.0.10':
                    break

        print(f'[<] Received EIGRP packet from {addr[0]}')
        if args['verbose']:
            p.printReadable()

        # set the neighbor address. from here we will talk with this device only
        selectedNeighbor = args['target']
        
        if args['point_to_point']:
            # 5a. SEND AN EMPTY REQUEST PACKET (AND ACK RECEIVED PACKET)
            #     ON POINT TO POINT CONNECTION WE CAN BYPASS THE ADJACENCY PROCESS
            #     THIS SHOULD TRIGGER AN UPDATE
            #     ALTERNATIVE WOULD BE TO CONTINUE THE EXCHANGE AS INTENDED TO COMPLETE THE INITIALIZATION SEQUENCE
            #     RFC 7868 5.3.4

            q = EIGRPPacket.fromValues(p.EIGRPHeaderVersion, 2, p.EIGRPFlags, seqnum, p.EIGRPSeqNum, 0, p.EIGRPAutonomousSysNum, b'')
            print(f'[>] Sending EIGRP packet to {selectedNeighbor}')
            s.sendto(q.IP4Payload, (selectedNeighbor, 0))

            # 6. RECEIVE UPDATE WITH DATA, STORE TLVS IN BUFFER
            while True:
                data, addr = s.recvfrom(1024)
                if addr[0] == selectedNeighbor:
                    p = EIGRPPacket(data)
                    if p.EIGRPOpCode == 1:
                        break

            print(f'[<] Received EIGRP packet from {addr[0]}')
            if args['verbose']:
                p.printReadable()

            # APPEND RESULTS TO ROUTE LIST
            for t in p.EIGRPTLVs:
                if ((t.EIGRPTLVTypeHigh << 8) + t.EIGRPTLVTypeLow) in routeTypes:
                    routeTLVs.append(t)
        else:
            # 5b. SEND OUR NULL UPDATE AND ACK RECEIVED PACKET
            q = EIGRPPacket.fromValues(p.EIGRPHeaderVersion, 1, p.EIGRPFlags, seqnum, p.EIGRPSeqNum, 0, p.EIGRPAutonomousSysNum, b'')
            print(f'[>] Sending EIGRP packet to {selectedNeighbor}')
            s.sendto(q.IP4Payload, (selectedNeighbor, 0))

            # 6. RECEIVE HELLO ACK
            while True:
                data, addr = s.recvfrom(1024)
                if addr[0] == selectedNeighbor:
                    p = EIGRPPacket(data)
                    if p.EIGRPOpCode == 5:
                        break

            print(f'[<] Received EIGRP packet from {addr[0]}')
            if args['verbose']:
                p.printReadable()

            # 7. RECEIVE UPDATE
            while True:
                data, addr = s.recvfrom(1024)
                if addr[0] == selectedNeighbor:
                    p = EIGRPPacket(data)
                    if p.EIGRPOpCode == 1:
                        break
            
            print(f'[<] Received EIGRP packet from {addr[0]}')
            if args['verbose']:
                p.printReadable()

            # 8. SEND UPDATE ( NO FLAGS, NO SEQ, ACK)
            q = EIGRPPacket.fromValues(p.EIGRPHeaderVersion, 1, 0, 0, p.EIGRPSeqNum, 0, p.EIGRPAutonomousSysNum, b'')
            print(f'[>] Sending EIGRP packet to {selectedNeighbor}')
            s.sendto(q.IP4Payload, (selectedNeighbor, 0))

            # 9. RECEIVE TOPOLOGY
            while True:
                data, addr = s.recvfrom(1024)
                if addr[0] == selectedNeighbor:
                    p = EIGRPPacket(data)
                    if p.EIGRPOpCode == 1:
                        break

            print(f'[<] Received EIGRP packet from {addr[0]}')
            if args['verbose']:   
               p.printReadable()

            # APPEND RESULTS TO ROUTE LIST
            for t in p.EIGRPTLVs:
                if ((t.EIGRPTLVTypeHigh << 8) + t.EIGRPTLVTypeLow) in routeTypes:
                    routeTLVs.append(t)
        
        for t in routeTLVs:
            parseRouteTLV(t)
    
    if args['mode'] == 'passive':
        print(f'[i] Started {args["mode"]} {args["protocol"]} scan')

        seenRouters = []
        print('[ ] Listening for incoming EIGRP HELLOs...')
        
        # create socket and join multicast group
        s = socket(AF_INET, SOCK_RAW, EIGRP_PROTO_N)
        mcast = struct.pack('=4sl', inet_aton(EIGRP_ALL_MCAST_GROUP), INADDR_ANY)
        s.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, mcast)
        s.settimeout(args['seconds_time_out'])

        try:
            c = 0
            while c < args['max_captures']:
                data, addr = s.recvfrom(1024)
                p = IP4Packet(data)
                if p.IP4Proto == 88:
                    print(f'[<] Received EIGRP packet from {addr[0]}')
                    if addr[0] not in seenRouters:
                        seenRouters.append(addr[0])
                    if args['verbose']:
                        p = EIGRPPacket(data)
                        p.printReadable()
                else:
                    print(f'[<] Received packet from {addr[0]} (protocol: {p.IP4Proto})')
                    if args['verbose']:
                        p.printReadable()
                c = c + 1
        except timeout:
            print('[X] Socket timeout. Terminating...')
            s.setsockopt(IPPROTO_IP, IP_DROP_MEMBERSHIP, mcast) # leave multicast group
            s.close()
            printPassiveResults(seenRouters)
            exit(1)
        except KeyboardInterrupt:
            s.setsockopt(IPPROTO_IP, IP_DROP_MEMBERSHIP, mcast) # leave multicast group
            s.close()
            printPassiveResults(seenRouters)
            exit(1)

        printPassiveResults(seenRouters)

    if args['mode'] == 'inject':
        print('[X] Injection mode is not yet implemented')
        pass

s.setsockopt(IPPROTO_IP, IP_DROP_MEMBERSHIP, mcast) # leave multicast group
s.close()

