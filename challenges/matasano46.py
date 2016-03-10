#matasano 6.46

import random
import string
from hashlib import sha1
from matasano39 import encrypt, decrypt, make_keypair
from matasano18 import bi2ba
import binascii
import base64

bitlength = 1024
e = 65537
n, d = make_keypair(bitlength, e)

def parity_oracle(encrypted):
    '''Given a ciphertext, return True if the
    corresponding plaintext is odd, or False if it is even'''
    decrypted_int = decrypt(n, d, encrypted, bitlength)
    if decrypted_int % 2:
        return True
    return False

b64msg = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
ptxt = base64.b64decode(b64msg)

encrypted = encrypt(n, e, ptxt, bitlength, outfmt='int')
res = parity_oracle(encrypted)

enc2 = encrypt(n, e, 2, bitlength)
lower = 0
upper = n
last_ptxt = ''
while True:
    encrypted = enc2 * encrypted % n
    newres = parity_oracle(encrypted)
    middle = (upper - lower)/2
    if newres:
        lower += middle
    else:
        upper -= middle
    #not quite hollywood, but not bad:
    print bi2ba(upper)
    #last byte is not reliable, maybe be fixable?
    
'''Comment:
I found you had to dig a little deep to
properly grok the algorithm here; the key
point that I found unobvious was this:
It's clear that the first time the wrap around the 
modulus occurs, it proves that n/2^k < plaintext < n/2^(k-1)
if it's on the kth doubling that the first wrap occurs.
What's less obvious is what you can deduce when the next doubling
either causes a wrap or doesn't. Suppose wrapping happens again
(i.e. the oracle returns 'odd'). That means that the *remainder* is
bigger than half the modulus, i.e. plaintext * 2^k - n > n/2.
So you get plaintext > 3*n/2^(k+1). This number is the halfway point
between the two bounds earlier established. Contrariwise, you deduce
that plaintext < 3*n/2^(k+1) if it doesn't wrap. This continues as you
go through more iterations, each time resetting either the lower
or upper bound to the midpoint.
'''



