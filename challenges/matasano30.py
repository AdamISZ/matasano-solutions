#matasano 4.30

import binascii
import matasano3
import os  
import random
import struct

from struct import pack
from binascii import hexlify


def make_words(byte_array):

    res = []

    for i in xrange(0, len(byte_array), 4):

        index = i/4
        res.append(byte_array[i+3])
        res[index] = (res[index] << 8) | byte_array[i+2]
        res[index] = (res[index] << 8) | byte_array[i+1]
        res[index] = (res[index] << 8) | byte_array[i]

    return res
        


def md4(message, cracks = None, pml = None, debug=False):
    """
    https://tools.ietf.org/html/rfc1320
    """

    # we'll need to remember this for later
    if pml:
        original_length = pml+len(message)
    else:
        original_length = len(message)

    message = [ord(c) for c in message]

    # add a '1' bit via a byte
    message += [0x80]

    mod_length = (original_length+1) % 64
    # padding to 448 % 512 bits (56 % 64 byte)
    if mod_length < 56:
        message += [0x00] * (56 - mod_length)
    else:
        message += [0x00] * (120 - mod_length)

    # add the length as a 64 bit big endian, use lower order bits if length overflows 2^64
    length = [ord(c) for c in pack('>Q', (original_length * 8) & 0xFFFFFFFFFFFFFFFF)]

    # add the two words least significant first
    message.extend(length[::-1])

    if debug:
        print "\nafter padding {0}".format([[hex(b) for b in message]])

    # initialize the registers to magic values
    if cracks:
        A, B, C, D = cracks
    else:
        A = 0x67452301
        B = 0xefcdab89
        C = 0x98badcfe
        D = 0x10325476
    
    # define F, G, and H
    def F(x,y,z): return ((x & y) | ((~x) & z))
    def G(x,y,z): return (x & y) | (x & z) | (y & z)
    def H(x,y,z): return x ^ y ^ z

    # round functions
    def FF(a,b,c,d,k,s): return ROL((a + F(b,c,d) + X[k]) & 0xFFFFFFFF, s)
    def GG(a,b,c,d,k,s): return ROL((a + G(b,c,d) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
    def HH(a,b,c,d,k,s): return ROL((a + H(b,c,d) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)

    # define a 32-bit left-rotate function (<<< in the RFC)
    def ROL(x, n): return ((x << n) & 0xFFFFFFFF) | (x >> (32-n))

    # turn the padded message into a list of 32-bit words
    M = make_words(message)
        
    # process each 16 word (64 byte) block
    for i in xrange(0, len(M), 16):

        X = M[i:i+16]
        # save the current values of the registers
        AA = A
        BB = B
        CC = C
        DD = D

        if debug:
            print "\n"
            print "A (initial): {0}".format(hex(A))
            print "B (initial): {0}".format(hex(B))
            print "C (initial): {0}".format(hex(C))
            print "D (initial): {0}".format(hex(D))

        # round 1

        # perform the 16 operations
        A = FF(A,B,C,D,0,3)
        D = FF(D,A,B,C,1,7)
        C = FF(C,D,A,B,2,11)
        B = FF(B,C,D,A,3,19)

        A = FF(A,B,C,D,4,3)
        D = FF(D,A,B,C,5,7)
        C = FF(C,D,A,B,6,11)
        B = FF(B,C,D,A,7,19)

        A = FF(A,B,C,D,8,3)
        D = FF(D,A,B,C,9,7)
        C = FF(C,D,A,B,10,11)
        B = FF(B,C,D,A,11,19)

        A = FF(A,B,C,D,12,3)
        D = FF(D,A,B,C,13,7)
        C = FF(C,D,A,B,14,11)
        B = FF(B,C,D,A,15,19)

        if debug:
            print "\n"
            print "A (round 1): {0}".format(hex(A))
            print "B (round 1): {0}".format(hex(B))
            print "C (round 1): {0}".format(hex(C))
            print "D (round 1): {0}".format(hex(D))

        # round 2

        # perform the 16 operations
        A = GG(A,B,C,D,0,3)
        D = GG(D,A,B,C,4,5)
        C = GG(C,D,A,B,8,9)
        B = GG(B,C,D,A,12,13)

        A = GG(A,B,C,D,1,3)
        D = GG(D,A,B,C,5,5)
        C = GG(C,D,A,B,9,9)
        B = GG(B,C,D,A,13,13)

        A = GG(A,B,C,D,2,3)
        D = GG(D,A,B,C,6,5)
        C = GG(C,D,A,B,10,9)
        B = GG(B,C,D,A,14,13)

        A = GG(A,B,C,D,3,3)
        D = GG(D,A,B,C,7,5)
        C = GG(C,D,A,B,11,9)
        B = GG(B,C,D,A,15,13)

        if debug:
            print "\n"
            print "A (round 2): {0}".format(hex(A))
            print "B (round 2): {0}".format(hex(B))
            print "C (round 2): {0}".format(hex(C))
            print "D (round 2): {0}".format(hex(D))

        # round 3

        A = HH(A,B,C,D,0,3)
        D = HH(D,A,B,C,8,9)
        C = HH(C,D,A,B,4,11)
        B = HH(B,C,D,A,12,15)

        A = HH(A,B,C,D,2,3)
        D = HH(D,A,B,C,10,9)
        C = HH(C,D,A,B,6,11)
        B = HH(B,C,D,A,14,15)

        A = HH(A,B,C,D,1,3)
        D = HH(D,A,B,C,9,9)
        C = HH(C,D,A,B,5,11)
        B = HH(B,C,D,A,13,15)

        A = HH(A,B,C,D,3,3)
        D = HH(D,A,B,C,11,9)
        C = HH(C,D,A,B,7,11)
        B = HH(B,C,D,A,15,15)

        if debug:
            print "\n"
            print "A (round 3): {0}".format(hex(A))
            print "B (round 3): {0}".format(hex(B))
            print "C (round 3): {0}".format(hex(C))
            print "D (round 3): {0}".format(hex(D))

        # increment by previous values
        A =  ((A + AA) & 0xFFFFFFFF)
        B =  ((B + BB) & 0xFFFFFFFF)
        C =  ((C + CC) & 0xFFFFFFFF)
        D =  ((D + DD) & 0xFFFFFFFF)

        if debug:
            print "\n"
            print "A (incrmnt): {0}".format(hex(A))
            print "B (incrmnt): {0}".format(hex(B))
            print "C (incrmnt): {0}".format(hex(C))
            print "D (incrmnt): {0}".format(hex(D))
            print "\n"

    # convert endian-ness for output
    A = hexlify(pack('<L', A))
    B = hexlify(pack('<L', B))
    C = hexlify(pack('<L', C))
    D = hexlify(pack('<L', D))
    
    return A + B + C + D

def keyed_md4(txt, k):
    return md4(k+txt)

def compute_padding_for_msg(msglen):
    '''Modified from above '''
    # append the bit '1' to the message
    # add a '1' bit via a byte
    pad = [0x80]

    mod_length = (msglen+1) % 64
    # padding to 448 % 512 bits (56 % 64 byte)
    if mod_length < 56:
        pad += [0x00] * (56 - mod_length)
    else:
        pad += [0x00] * (120 - mod_length)

    # add the length as a 64 bit big endian, use lower order bits if length overflows 2^64
    length = [ord(c) for c in pack('>Q', (msglen * 8) & 0xFFFFFFFFFFFFFFFF)]

    # add the two words least significant first
    return ''.join(map(chr, pad + length[::-1]))

if __name__ == '__main__':
    '''Reimplement the LE attack from challenge 29'''
    testmsg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    testk = os.urandom(random.randint(1,32))
    #testk = '1da_'*4
    first_digest = keyed_md4(testmsg, testk)
    print 'keyed sha: '+ first_digest
    print 'padding is: '+binascii.hexlify(compute_padding_for_msg(len(testk+testmsg)))
    print '\n'
    want_to_forge = ';admin=true'
    for klg in range(33): 
        #calculate the exact padding bytes there would have been if
        #this was the correct key length
        pad = compute_padding_for_msg(klg + len(testmsg))

        #Extract the 5 h values from the digest (this is the state vector for the hash fn)
        first_digest_bin = binascii.unhexlify(first_digest)
        cracks = []
        for a in range(4):
            bts = first_digest_bin[a*4:a*4+4][::-1]
            cracks.append(int(binascii.hexlify(bts),16))

        #when forging we also need to pass the length of the message *including*
        #the 'glue padding', i.e. the padding bytes from the previous unforged message.
        forge_output = md4(want_to_forge, cracks, pml=klg + len(testmsg) + len(pad))
        
        real_output = keyed_md4(testmsg + pad + want_to_forge, testk)
        
        if real_output == forge_output:
            print '**Success!'
            print 'Key length was: '+str(klg)
            print 'We forged a keyed hash for this message: '
            print testmsg + pad + want_to_forge
            print '.. without knowing the key. The hash was: '
            print real_output
            exit(0)
    print 'failed!'    