#matasano 6.43

import random
from hashlib import sha1
from matasano39 import inv
from matasano18 import bi2ba
import binascii

#The provided DSA parameters
p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1

q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
 
g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

given_sig = (548099063082341131477253921760299949438196259240, 857042759984254168557880549501802188789837994940)
given_pubkey = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
given_string = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"

def m2int(m, H=sha1):
    return int(eval('0x'+H(m).hexdigest()))

def get_random_key():
    '''NEVER do this for real!
    random module is not crypto-secure.'''
    return random.randint(1, q)

def privtopub(priv):
    #print 'using g: '
    #print g
    return pow(g, priv, p)

def sign(m, priv, k=None):
    '''The k paramater allows us to test
    a broken implementation where k is fixed'''
    while True:
        k = k if k else get_random_key()
        r = privtopub(k) % q
        inv_k = inv(k, q)
        s = (inv_k * (m2int(m) + priv * r)) % q
        if r!=0 and s!=0: break
    return (r,s)

def verify(m, sig, pub):
    r, s = sig
    if r==0 or s==0:
        print 'invalid zero in sig'
        return False
    w = inv(s, q)
    u1 = (m2int(m) *  w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(pub, u2, p)) % p) % q
    return True if v==r else False

def recover_privkey_from_nonce(m, sig, k):
    r, s = sig
    r_inv = inv(r, q)
    return (((s*k) - m2int(m))* r_inv) % q

if __name__ == '__main__':
    privkey = get_random_key()
    pubkey = privtopub(privkey)
    #Test sign/verify
    m = 'I myself am quite a tolerable, practical magician.'
    sig = sign(m, privkey)
    print 'got signature: '
    print sig
    if verify(m, sig, pubkey):
        print "verifies OK"
    else:
        print "Failed to verify"
    
    #Test recovery with arbitrary broken nonce:
    k = get_random_key()
    sig = sign(m, privkey, k=k)
    print 'got signature with known nonce: '
    print sig
    #Attempt to recover privkey:
    deduced_privkey = recover_privkey_from_nonce(m, sig, k)
    if deduced_privkey == privkey:
        print "Successfully recovered privkey"
    else:
        print "failed to recover privkey"
    
    #Now we try to crack the puzzle in 43.
    assert sha1(given_string).hexdigest()== "d2d0714f014a9784047eaeccf956520045c45265"
    
    #The given info is that k < 2^16, so we can search.
    #We'll try each one and recover against the given signature.
    #For each value, check whether pubkey of the recovered privkey
    #matches the given pubkey (and sanity check the fingerprint at the end).
    
    for k in range(2**16):
        guess_privkey = recover_privkey_from_nonce(given_string, given_sig, k)
        if privtopub(guess_privkey) == given_pubkey:
            print "Found the private key, it is: "
            print guess_privkey
            print "Its SHA-1 fingerprint is: "
            #NB 'hex' in python prepends 0x and appends L for longs
            print sha1(hex(guess_privkey)[2:-1]).hexdigest()
            break
        if not k%1000:
            print "Still trying, k=" + str(k)
    