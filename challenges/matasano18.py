#matasano 3.18

import slowaes
import base64
import binascii
import matasano3
import os

def bi2ba(bigint,fixed=None):
    m_bytes = []
    while bigint != 0:
        b = bigint%256
        m_bytes.insert( 0, b )
        bigint //= 256
    if fixed:
        padding = fixed - len(m_bytes)
        if padding > 0: m_bytes = [0]*padding + m_bytes
    return bytearray(m_bytes)

def aes_ctr_crypt_block(pt, k, nonce, ctr, bs):
    '''Provide nonce and ctr as integers.
    They will be converted to 64 bit LE bytestreams.
    Note that if len(pt)%bs, we still produce the partial.
    (Stream cipher)
    '''
    aes = slowaes.AES()
    #construct counter block:
    counter_block = bi2ba(nonce, 8)[::-1] + bi2ba(ctr, 8)[::-1]
    keystream = aes.encrypt(map(ord, str(counter_block)), map(ord, k), bs)
    ct = matasano3.xor(keystream[:len(pt)], map(ord, pt), fmt='ord')
    return binascii.unhexlify(ct)

def aes_ctr_crypt(pt, k, nonce, bs=16):
    '''Encrypt plaintext or decrypt ciphertext
    with counter 64 bit LE, counting upwards 
    from 0 for the first block.'''
    blocks = matasano3.get_blocks(pt, bs)
    ct = ''
    for i, b in enumerate(blocks):
        f = [x for x in b if x is not None]
        ct += aes_ctr_crypt_block(''.join(f), k, nonce, i, bs)
    return ct    

if __name__ == '__main__':
    bs = 16
    k = 'YELLOW SUBMARINE'
    pt64 = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    pt = base64.b64decode(pt64)
    print "len pt: "+str(len(pt))
    #solve 'challenge'
    print aes_ctr_crypt(str(pt), k, 0, bs)
    print str(len(aes_ctr_crypt(str(pt), k, 0, bs)))
    #try some test vectors
    randstring = os.urandom(33)
    tests = ['00000000', 'a',randstring]
    for ke in [k, os.urandom(16)]:
        for i, t in enumerate(tests):
            encrypted = aes_ctr_crypt(t, ke, i)
            assert aes_ctr_crypt(encrypted, ke, i)==t, 'Test failed'
    
    print 'tests OK'