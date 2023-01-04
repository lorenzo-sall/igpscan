from igpscan_protocols.ipv4 import *
from igpscan_required.igpscanutils import *

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

# this class represent the TLV (type, length, value) portion of an EIGRP packet 
class EIGRPTLV:
    def __init__(self, th, tl, l, v):
        self.EIGRPTLVTypeHigh = th
        self.EIGRPTLVTypeLow = tl
        self.EIGRPTLVLen = l
        self.EIGRPTLVRawValue = v

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