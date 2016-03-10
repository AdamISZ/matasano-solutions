#matasano 2.13

import slowaes
import base64
import binascii
import collections
import matasano3
import matasano7
import matasano10
import os
import random

fixed_k = '123a'*4

def cookie_parse(c):
    pairs = c.split('&')
    obj = {}
    for p in pairs:
        if p.count('=') != 1:
            raise ValueError("Invalid key value pair string")
        k,v = p.split('=')
        obj[k]=v
    return obj

def profile_for(email, i=10):
    uid = str(i)
    illegal = ['&','=']
    for ill in illegal:
        if ill in email:
            raise ValueError("Illegal character, not processing")
    return '&'.join(['email='+email, 'uid='+uid, 'role=user'])

def encrypt_profile(ep, k=None):
    if not k:
        k = fixed_k
    return matasano7.ecb_encrypt(ep, k)

def decrypt_profile(eep, k=None):
    if not k:
        k = fixed_k
    ep = matasano7.ecb_decrypt(eep, k)
    return cookie_parse(ep)

    
if __name__ == '__main__':
    test_profile = profile_for("foo@bar.com")
    print test_profile
    encrypted_test_profile = encrypt_profile(test_profile)
    print binascii.hexlify(encrypted_test_profile)
    print decrypt_profile(encrypted_test_profile)
    part1_encrypted_p = encrypt_profile(profile_for('foooo@bar.com'))
    assert len(part1_encrypted_p)==48, 'wrong ecrypted length'
    block12 = part1_encrypted_p[:32]
    part2_encrypted_p = encrypt_profile(
        profile_for('\x0a'*10 + 'admin'+'\x0b'*11 +'@bar.com'))
    print 'length of part2 output is: '+str(len(part2_encrypted_p))
    block2prime = part2_encrypted_p[16:32]
    crafted_enc_p = block12+block2prime
    print decrypt_profile(crafted_enc_p)
#strategy: clue is in the title! cut and paste.
#part 1: generate an email long enough that 'role=' is at
#the end of a block (block 2 probably). Then those will be the
#starting blocks.
#part 2: create the input for 'email=[padding]admin[padding]@bar.com'
#so that the 2nd block is exactly the encryption of 'admin[padding]'
#then take the first two blocks from Part 1 and the last block from part 2
#and pass it into decrypt_profile
# Part 1:
# feed in 'email=foooo@bar.com'
# Block 1:
# email=foooo@bar. 
# Block 2:
# com&uid=10&role=
# Block 3:
# user+pkcs7padding
# Store block 1 and block 2
# Part 2:
# feed in 'email='+'\x0a'*10 + 'admin'+'\x0b'*11 +'@bar.com'
# Block 1':
# 'email='+'\x0a'*10
# Block 2':
# 'admin'+'\x0b'*11
# Finally:
# construct Block 1 + Block 2 + Block 2'
# feed this into decrypt
