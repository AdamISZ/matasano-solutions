#matasano 6.42
 
import binascii
import os
import random
from hashlib import sha1
from matasano18 import bi2ba
from matasano39 import inv, make_keypair, encrypt, decrypt
from matasano40 import iroot
from Crypto.PublicKey import RSA
import gmpy

trial_text = "Hi mom."

def root3rd(x):
    '''An implementation of cube root that stores the result
    as double precision, and which returns the result even if the
    cube is not exact (this error condition could be caught by uncommenting
    the y^3 check)
    '''
    y, y1 = None, 2
    while y!=y1:
        y = y1
        y3 = y**3
        d = (2*y3+x)
        y1 = (y*(y3+2*x)+d//2)//d
    #if y*y*y != x:
    #    return None
    return y

def weakly_verify_rsa_sig(msg, sig, n, bytelength, e=3):
    '''Pass sig as binary string and n,e as integers'''
    #First, pass the sig through the "encrypt" primitve
    #to get the plaintext:
    ptxt = encrypt(n, e, int(eval('0x'+binascii.hexlify(sig))))
    ptxt = bi2ba(ptxt, fixed=bytelength)
    #here we check the padding; (there are other exploits
    #if the implementation doesn't even do this, but 
    #Bleichenbacher's attack does not require that)
    if ptxt[:2] != '\x00\x01':
        raise Exception("Padding error in signature, not valid.")
    ptxt = ptxt[2:]
    try:
        first_zero = ptxt.index('\x00')
        if not all([x==255 for x in ptxt[2:first_zero]]):
            return False
    except ValueError:
        print 'Padding error in signature, not valid'
        raise
    ptxt = ptxt[first_zero+1:]
    #real implementation would deal with ASN.1, here I'll
    #just treat it as a random chunk of 15 bytes and ignore it.
    ptxt = ptxt[15:]
    msghash, remaining = ptxt[:20], ptxt[20:]
    
    #HERE IS THE ERROR: should check 'right aligned':
    #if remaining:
    #    print 'incorrect alignment in signature, not valid.'
    #    return False
    
    #verify the signature hash
    if msghash != sha1(msg).digest():
        return False
    else:
        return True
    
if __name__ == '__main__':
    '''Bleichenbacher '06 signature forgery attack.
    First write an insecure implementation of signature verification.
    Then build a forgery based on cube rooting something that looks
    vaguely right but doesn't check padding alignment.
    Hal Finney's writeup: 
    https://www.ietf.org/mail-archive/web/openpgp/current/msg00999.html
    '''
    bitlength = 1024 # must be power of 2
    bytelength = bitlength/8
    e = 3
    signer_mod, signer_d = make_keypair(bitlength, e)
    
    #Step 1. ASN.1 bytes for the RSA SHA-1 sig
    asn1_string = "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"
    
    #Step 2. Take the hash of the message we want to sign; this is our forgery.
    hash_string = sha1(trial_text).digest() #20 bytes
    print 'using message hash string: '
    print binascii.hexlify(hash_string)
    
    #number of ff padding bytes in our PKCS1 1.5; can be anything according
    #to the rules; feel free to set it to something else.
    Y = 3
    fake_sig_msg = '\x00\x01' + '\xff'*Y + '\x00' + asn1_string + hash_string
    #we're looking for an approx cube root; just pad out with zeros and
    #see what comes out; it won't always work, but it often will.
    fake_string = fake_sig_msg + '\x00'* (bytelength - Y - 3 - 15 - 20)
    fake_string_int = int(eval('0x'+binascii.hexlify(fake_string)))
    #Note: pow does not store enough precision in the result
    #cube_root = pow(fake_string_int, 1/3.0)
    #This custom cube-rooter works:
    sig_int = root3rd(fake_string_int)
    binarised_cube_root = bi2ba(sig_int, fixed=bytelength)
    #now we have a binary string which is a candidate cube root, i.e. a 
    #candidate forged signature. Try; if it fails it will be on the last
    #byte rounding error, just tweak the integer value until it works.
    while not weakly_verify_rsa_sig(trial_text, binarised_cube_root,
                             signer_mod, bytelength, e=e):
        print 'no luck, trying again'
        sig_int += 1
        binarised_cube_root = bi2ba(sig_int, fixed=bytelength)
    print 'success: here is the forged signature for "' + trial_text + '":'
    print binascii.hexlify(binarised_cube_root)
    #Notice: the result doesn't depend on the random keypair we generated.
    #That's because cubing doesn't wrap around so the modulus doesn't matter.
    

#LEAVING THESE NOTES HERE IN CASE USEFUL SOMETIME;
#I earlier tried to implement Hal Finney's notes, but they seemed
#to be dependent on the modulus being a multiple of 3 (3072);
#not true for the common 1024 or 2048.
#
#We're going to try to build a signature without using signer_d
#I'll follow a generalisation of Hal Finney's attack description.
#Suppose the number of FF bytes is Y.
#Suppose the position at which the (ASN1+HASH) bytes starts is 2^K
#then the whole byte string should correspond to the number:
#2^(Y+K+1) - 2^K + D*2^(K-288)
#where it is assumed that ASN1+HASH consists of 36 bytes = 288 bits.
#Now, if D = 2^288 - N, we have:
#sig value = 2^(Y+K+1) - N *2^(K-288)
#and this is a number for which we can easily get a cube root, as long
#as we don't care too much about the lower order bits. We need two
#things: first, that N is divisible by 3, and to find a number a s.t.
#(2^((Y+K+1)/3) - (N/3)*2^a)^3 = 2^(Y+K+1) - N*2^(K-288) + lower order bits.
#Then simple algebra will show that a satisifies:
# a = (K-Y-2)/3 - 288.
#Also, in order that the remaining two cubic terms don't overlap into the
#part we care about, we need the ASN1+HASH length to be less than Y+1
#which means Y must be at least 36 or so bytes; we choose ~50 as a reasonable
#value.