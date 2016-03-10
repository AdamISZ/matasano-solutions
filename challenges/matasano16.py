#matasano 2.16

import slowaes
import base64
import binascii
import matasano3
import matasano7
import matasano10
import matasano12
import os
import random

def aes_cbc_modified(s, k=None, iv=None):
    if not k:
        k = matasano12.fixed_k
    if not iv:
        iv = os.urandom(16)
    #sanitize input
    s = s.replace(';','')
    s = s.replace('=','')
    prepend = "comment1=cooking%20MCs;userdata="
    append = ";comment2=%20like%20a%20pound%20of%20bacon"
    tbe = prepend + s + append
    return matasano10.aes_cbc_encrypt(tbe, k, iv)

def aes_cbc_decrypt_to_object(s, k=None, highasciicheck=False):
    if not k:
        k = matasano12.fixed_k
    decrypted = matasano10.aes_cbc_decrypt(s, k)
    print 'got decrypted: '+decrypted
    print 'got decrypted hex: '+binascii.hexlify(decrypted)
    
    #High ascii check option is used for challenge 4.27
    if highasciicheck:
        if any([ord(_)>128 for _ in decrypted]):
            #in practice this could be an Exception,
            #but let's return the error string so as to
            #avoid a manual copy-paste step in challenge 27
            return "Non ascii string: " + s
        
    sections = decrypted.split(';')
    print 'got sections: '
    print sections
    obj = {}
    for s in sections:
        if s.count('=') != 1:
            raise Exception("invalid plaintext")
        k,v = s.split('=')
        obj[k]=v
    print 'obj is:'
    print obj
    if 'admin' not in obj.keys():
        return False
    if obj['admin'] != 'true':
        return False
    return True

if __name__ == '__main__':
    bs = 16
    #attack string is 2 blocks of any old crap
    istring = 'A'*32
    ct = aes_cbc_modified(istring)
    print binascii.hexlify(ct)
    if aes_cbc_decrypt_to_object(ct):
        print 'success'
    else:
        print 'failed'
    #now we attack, using the generated ciphertext
    third_block = ct[48:64] #skip IV
    #this was the encryption of %20MCs;userdata=
    desired_block= 'AAAAA;admin=true'
    crafted_block = ''
    for i, b in enumerate(third_block):
        #the corresponding byte in the third block pt is always 'A'
        tweak = ord(desired_block[i]) ^ ord('A')
        crafted_block += chr(ord(b) ^ tweak)
    crafted_ct = ct[:48]+crafted_block+ct[64:]
    #pass through decryption oracle
    if aes_cbc_decrypt_to_object(crafted_ct):
        print 'success attack'
    else:
        print 'failed attack'
