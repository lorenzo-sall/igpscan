from igpscan_protocols.ipv4 import *
from igpscan_required.igpscanutils import *

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

