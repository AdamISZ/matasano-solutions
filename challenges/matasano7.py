#matasano 1.7

import slowaes
import base64
import matasano3

def ecb_decrypt(dctxt, k, bs = 16):
    k = map(ord, k)
    aes = slowaes.AES()
    #split ciphertext into 128 bit blocks
    blocks = matasano3.get_blocks(dctxt, bs)
    ptext = []
    for b in blocks:
        ctxt = map(ord, b)
        ptext.append(aes.decrypt(ctxt, k, bs))
    return slowaes.strip_PKCS7_padding(''.join(
        [''.join(map(chr, x)) for x in ptext]))

def ecb_encrypt(ptxt, k, bs = 16):
    pt_padded = slowaes.append_PKCS7_padding(ptxt)
    k = map(ord, k)
    aes = slowaes.AES()
    blocks = matasano3.get_blocks(pt_padded, bs)
    ctxt = []
    for b in blocks:
        pt = map(ord, b)
        ctxt.append(aes.encrypt(pt, k, bs))
    return ''.join([''.join(map(chr, x)) for x in ctxt])

if __name__ == '__main__':
    block_size = 16
    with open('7.txt','rb') as f:
        ctxt = f.read()
    k = "YELLOW SUBMARINE"
    dctxt = base64.b64decode(ctxt)    
    print ecb_decrypt(dctxt, k, block_size)
    assert ecb_encrypt(ecb_decrypt(dctxt, k, block_size), k, block_size) == dctxt

