import argparse
import struct
#import socket
#from socket import *
#from struct import *
from igpscan_required.igpscanutils import *
from igpscan_protocols.ipv4 import *
from igpscan_protocols.ospf import *
from igpscan_protocols.eigrp import *


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

