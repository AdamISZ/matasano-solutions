#matasano 5.39
 
import binascii
import os
from matasano18 import bi2ba
from Crypto.PublicKey import RSA

# Extended Euclidean Algorithm
# for inverse
def inv(a, n):
    if a % n == 0:
        raise ValueError("Cannot find inverse of zero")
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    #note that this crude code returns ZERO if there is NO INVERSE!!
    return lm % n

def get_two_primes(bits):
    #use the RSA function in Crypto to generate two primes p, q, but don't
    #use the other features; that's cheating.    
    dummyKey = RSA.generate(bits)
    p = getattr(dummyKey.key, 'p')
    q = getattr(dummyKey.key, 'q')
    return (p, q)

#needed for some later challenges
def encrypt(modulus, exponent, msg, bitlength=2048, outfmt=None):
    '''Take a message as integer and encrypt to
    a pubkey consisting of modulus modulus and
    exponent exponent and bitlength bitlength.
    Format is binary or integer.'''
    if isinstance(msg, str):
        message_int = int(eval('0x'+binascii.hexlify(msg)))
    elif isinstance(msg, int) or isinstance(msg, long):
        message_int = msg
    else:
        raise NotImplementedError
    encrypted = pow(message_int, exponent, modulus)
    if isinstance(msg, str) and not outfmt:
        return bi2ba(encrypted, fixed=bitlength/8)
    elif isinstance(msg, int) or isinstance(msg, long) or outfmt=='int':
        return encrypted
    else:
        raise NotImplementedError

def decrypt(modulus, decrypt_exp, msg, bitlength=2048, outfmt=None):
    if isinstance(msg, str) or isinstance(msg, bytearray):
        encrypted_int = int(eval('0x'+binascii.hexlify(msg)))
    elif isinstance(msg, int) or isinstance(msg, long):
        encrypted_int = msg
    else:
        raise NotImplementedError
    decrypted = pow(encrypted_int, decrypt_exp, modulus)
    if isinstance(msg, int) or isinstance(msg, long) or outfmt=='int':
        return decrypted
    elif isinstance(msg, str) or isinstance(msg, bytearray):
        return bi2ba(decrypted, fixed=bitlength/8)
    else:
        raise NotImplementedError

def make_keypair(bitlength, e):
    while True:
        p, q = get_two_primes(bitlength)
        n = p*q
        et = (p-1)*(q-1)
        d = inv(e, et)        
        if (d*e)%et == 1:
            break    
    return (n, d)

if __name__ == '__main__':
    '''Basic RSA implementation.
    '''
    bitlength = 2048 # must be power of 2
    e = 3
    n, d = make_keypair(bitlength, e)
    #try encrypting; crude (and textbook!) is restricted to the same
    #number of bits as the pubkey (bitlength here)
    message = "Why I myself am quite a tolerable practical magician."
    message_int = int(eval('0x'+binascii.hexlify(message)))
    print 'message int is: '+str(message_int)
    ciphertext = pow(message_int, e, n)
    ciphertext_otw = bi2ba(ciphertext, fixed=bitlength/8)
    print 'ciphertext is: '+ binascii.hexlify(ciphertext_otw)
    
    #try decrypting
    ciphertext = int(eval('0x'+binascii.hexlify(ciphertext_otw)))
    decrypt_int = pow(ciphertext, d, n)
    print 'got decrypt int: '+str(decrypt_int)
    print 'decrypted is: '+bi2ba(decrypt_int, fixed=bitlength/8)