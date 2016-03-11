#matasano 2.10

import slowaes
import base64
import binascii
import collections
import matasano3
import matasano7

def aes_cbc_decrypt(ct, k, bs=16, nopad=False):
    aes = slowaes.AES()
    #split ciphertext into blocks
    blocks = matasano3.get_blocks(ct, bs)
    cb = blocks[0]
    #for each block, aes decrypt, then xor with previous ct to get pt
    pt = []
    for bl in blocks[1:]:
        decrypted = aes.decrypt(map(ord, bl), map(ord, k), bs)
        pt.append(binascii.unhexlify(matasano3.xor(map(ord, cb), decrypted, fmt='ord')))
        cb = bl
    #verify padding in last block
    plaintext = ''.join(pt)
    if nopad:
        return pt
    else:
        return slowaes.strip_PKCS7_padding(plaintext)

def aes_cbc_encrypt(pt, k, iv, bs=16):
    aes = slowaes.AES()
    pt_padded = slowaes.append_PKCS7_padding(pt)
    #split plaintext into blocks
    blocks = matasano3.get_blocks(pt_padded, bs)
    cb = iv
    #for each block, xor with previous ciphertext, then aes encrypt
    ct = [iv]
    for bl in blocks:
        xored = binascii.unhexlify(matasano3.xor(cb, bl, fmt='bin'))
        encrypted = aes.encrypt(map(ord, xored), map(ord, k), bs)
        new_ct = ''.join(map(chr, encrypted))
        ct.append(new_ct)
        cb = new_ct
    return ''.join(ct)

if __name__ == '__main__':
    block_size = 16
    with open('10.txt','rb') as f:
        ctxt = f.read()    
    dctxt = base64.b64decode(ctxt)
    k = "YELLOW SUBMARINE"
    iv = '\x00'*16
    x  = aes_cbc_decrypt(iv+dctxt, k)
    print 'got decryption: '
    print x
    print '\n'*3
    assert aes_cbc_encrypt(x, k, iv) == iv+dctxt, "decrypt-encrypt round trip check failed"
    print 'round trip check passed'
