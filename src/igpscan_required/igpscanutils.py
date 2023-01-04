from socket import *

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
    
    # NEEDS TO BE RECURSIVE (TO DO)
    carry_around = (sum_no_carry & 0xffff) + (sum_no_carry >> 16)
    complement = ~carry_around & 0xFFFF

    return complement