#matasano 4.26

import slowaes
import base64
import binascii
import matasano3
import matasano12
import matasano18
import os    

def aes_ctr_modified(s, k=None):
    if not k:
        k = matasano12.fixed_k
    #sanitize input
    s = s.replace(';','')
    s = s.replace('=','')
    prepend = "comment1=cooking%20MCs;userdata="
    append = ";comment2=%20like%20a%20pound%20of%20bacon"
    tbe = prepend + s + append
    return matasano18.aes_ctr_crypt(tbe, k, 0)

def aes_ctr_decrypt_to_object(s, k=None):
    if not k:
        k = matasano12.fixed_k
    decrypted = matasano18.aes_ctr_crypt(s, k, 0)
    print 'got decrypted: '+decrypted
    print 'got decrypted hex: '+binascii.hexlify(decrypted)
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
    #attack string is 1 block of any old crap
    istring = 'A'*16
    ct = aes_ctr_modified(istring)
    print binascii.hexlify(ct)
    if aes_ctr_decrypt_to_object(ct):
        print 'success'
    else:
        print 'failed'
    #now we attack, using the generated ciphertext
    third_block = ct[32:48]
    #this was the encryption of %20MCs;userdata=
    desired_block= 'AAAAA;admin=true'
    crafted_block = ''
    for i, b in enumerate(third_block):
        #the corresponding byte in the third block pt is always 'A'
        tweak = ord(desired_block[i]) ^ ord('A')
        crafted_block += chr(ord(b) ^ tweak)
    crafted_ct = ct[:32]+crafted_block+ct[48:]
    #pass through decryption oracle
    if aes_ctr_decrypt_to_object(crafted_ct):
        print 'success attack'
    else:
        print 'failed attack'    