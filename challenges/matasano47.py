#matasano 6.47

import random
import string
import os
import math
from hashlib import sha1
from matasano39 import encrypt, decrypt, make_keypair, inv
from matasano18 import bi2ba
import binascii
import base64
from Crypto.Util.number import getPrime

bitlength = 256
e = 65537

def get_small_rsa_key(bitlength, e):
    '''Given a public RSA exponent e and a keysize
    in bits bitlength, return a public modulus n
    and a private exponent d.
    '''
    #Because Crypto.RSA recoils
    #in horror at generating with n<2^1024,
    #we'll construct a key by hand using the prime
    #generation code.    
    p, q = [getPrime(bitlength/2) for _ in range(2)]
    n = p*q
    phi = (p-1)*(q-1)
    d = inv(e, phi)
    return (n, d)

def pkcs1v15_oracle(encrypted):
    '''Given a ciphertext, return True if the
    leading bytes correspond to pkcs1 v1.5 for encryption,
    i.e. they must be 00 and 02, return True if so and False otherwise.
    '''
    decrypted = bi2ba(decrypt(n, d, encrypted, bitlength), fixed=bitlength/8)
    return True if decrypted[:2]=='\x00\x02' else False


def pkcs1v15_pad_for_encryption(m):
    '''Prepend correct padding for pkcs1 v1.5 encryption to string m.
    None of the padding bytes may be zero, and a zero byte
    is used as a delimiter at the end of the padding
    to mark the start of the message.
    '''
    padding_length = (bitlength/8) - 2 -1 - len(m)
    padding = '\x00'
    while '\x00' in padding:
        padding = os.urandom(padding_length)
    return '\x00'+'\x02'+padding+'\x00'+m

n, d = get_small_rsa_key(bitlength, e)
msg = "kick it, CC"
pmsg = pkcs1v15_pad_for_encryption(msg)
c = encrypt(n, e, pmsg, bitlength, outfmt='int')

#Bleich. '98 limited version
#Step 1 is skipped as we work with a ciphertext.
#Step 2a. Find a s1 that is pkcs conformant.
B = 2**(bitlength-16)
s1 = int(n/(3*B))
M = [(2*B, 3*B-1)]
print "Preparing first s value, can take 30sec or so.."
while True:
    encs1 = encrypt(n, e, s1, bitlength)
    c1 = c * encs1 % n
    oracle_check = pkcs1v15_oracle(c1)
    if oracle_check:
        break
    s1 += 1
#sanity check: we found a ciphertext that has correct bytes?
print "Here is ciphertext*s1, it should have 00 02 as its leading bytes: "
print binascii.hexlify(bi2ba(decrypt(n, d, c1, bitlength), fixed=bitlength/8))
raw_input("Press enter to continue")

s = s1
while len(M)>1 or M[-1][1] != M[-1][0]:
    if len(M) > 1:
        #deferred to last challenge (48)
        print 'cant do that yet'
        exit(0)
    #2c - choose an r value, then search for s in the bounds
    #until pkcs found, then recompute M and continue
    found = False
    a, b = M[-1]
    r = int(2*((b*s - 2*B)/n))-1
    while not found:
        r += 1
        for s in range(int((2*B + r*n)/b), int((3*B + r*n)/a)+1):
            encs = encrypt(n, e, s, bitlength)
            if pkcs1v15_oracle(c * encs % n):
                found = True
                break
    #step 3 recompute M; for now assume just one
    #of form (max(a, ceil(2B+rn/s)),min(b,floor(3B-1+rn/s)))
    
    #this is needed to do ceiling properly for ints in Python2
    q, rem = divmod((2*B + r*n), s)
    new_a = q if rem==0 else q+1
    a = max([a, new_a])
    #floor is just int() of course
    b = min([b, int((3*B -1 + r*n)/s)])
    M = [(a, b)]
    if b - a < 1:
        print "cracked the message, it's:"
        x =  bi2ba(a,fixed=bitlength/8)
        print x[1:][x[1:].find('\x00')+1:]
        exit(0)
    
    
    
