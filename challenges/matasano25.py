#matasano 4.25

import slowaes
import base64
import binascii
import matasano3
import matasano7
import matasano18
import os    

def edit(ctxt, k, offset, newtxt, nonce, bs=16):   
    #choose the block to do
    block_num = offset / bs
    offset_in_block = offset % bs
    decrypted = list(matasano18.aes_ctr_crypt_block(
        ctxt[block_num*16:(block_num+1)*16], k, nonce, block_num, bs))
    decrypted[offset_in_block]= newtxt
    encrypted = matasano18.aes_ctr_crypt_block(
        decrypted, k, nonce, block_num, bs)[offset_in_block]
    return encrypted

if __name__ == '__main__':
    bs = 16
    #recover the original text
    #using the secret key from challenge 7
    with open('25.txt','rb') as f:
        ctxt = f.read()
    ecbk = "YELLOW SUBMARINE"
    dctxt = base64.b64decode(ctxt)    
    ecb_decrypted = matasano7.ecb_decrypt(dctxt, ecbk, bs)
    
    #set a new secret key for this exercise:
    k = os.urandom(16)
    
    #encrypt that plaintext using AES-CTR
    ctxt = matasano18.aes_ctr_crypt(ecb_decrypted, k, 0)
    
    #use 'edit' fn above to recover the keystream byte-by-byte:
    keystream = ''
    for i in range(len(ecb_decrypted)):
        edit_ctxt = edit(ctxt, k, i, chr((ord(ctxt[i])+1)%256), 0)
        keystream += chr(ord(edit_ctxt) ^ (ord(ctxt[i])+1)%256)
        
    #xor the keystream with the plaintext we injected
    orig_ptxt = ''.join(
        [chr(_[0] ^ _[1]) for _ in zip(map(ord, keystream), map(ord, ctxt))])
    
    print 'Passed'  if orig_ptxt==ecb_decrypted else 'Failed'
    