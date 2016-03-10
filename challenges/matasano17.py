#matasano 3.17

import slowaes
import base64
import binascii
import matasano3
import matasano7
import matasano10
import matasano12
import os
import random

ts = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

def validate_aes_cbc_padding(ct, k=None):
    if not k:
        k = matasano12.fixed_k
    try:
        matasano10.aes_cbc_decrypt(ct, k)
    except ValueError as e:
        #commented print functions for debug/cheat, expose padding
        #print 'got error: '+repr(e)
        #print matasano10.aes_cbc_decrypt(ct, k, nopad=True)
        return False
    #print 'got success: '
    #print matasano10.aes_cbc_decrypt(ct, k, nopad=True)
    return True


if __name__ == '__main__':
    bs = 16
    #first get untampered ciphertexts for each:
    tsc = []
    fds = []
    for t in ts:
        tsc.append(matasano10.aes_cbc_encrypt(t, 
                                              matasano12.fixed_k, os.urandom(16)))
    #we proceed as if not knowing the key, only using the padding oracle fn
    #start with the first (non-IV) block (c[1]).
    # start with the last byte.
    #  loop over guesses g=0..255
    #   malleate the last byte to: c[0][-1] ^ g ^ 01
    #   send c[:2] to padding oracle (remember c[0] is IV); if true, then p[1][-1] == g
    # next the prev-to-last byte: we know last byte of p[1] = L
    #  loop over guesses g=0..255
    #   set c[0][-1] to c[0][-1] ^ L ^ 02
    #   set c[0][-2] to c[0][-2] ^ g ^ 02
    #   send c[:2] to padding oracle; if true then p[1][-2] == g
    # repeat for all in block up to padding x15 for 1st byte
    
    for k, trial_ct in enumerate(tsc):
        full_decryption = ''
        print 'trial ct len: '+str(len(trial_ct))
        for p in range(len(trial_ct)/16-1):
            #print 'starting loop with p : '+str(p)
            known_for_block = ''
            for i in range(16):
                found=False
                #print 'starting loop with knownfb= '+known_for_block
                for g in range(256):
                    malleated = ''    
                    for j in range(i):
                        #add the tweaks for the padding bytes of *already known* bytes
                        malleated = chr(ord(
                            trial_ct[16*p + 16-j-1]) ^ ord(
                                known_for_block[-1-j]) ^ (i+1))+malleated
                    
                    #Prepend the tweaked byte for the guess.
                    #Special rule for final block: final block *DOES* have valid
                    #padding, so we must not try xoring our guess with itself,
                    #else we must get valid padding by definition.
                    if p == len(trial_ct)/16-2 and g==(i+1):
                        if g==1 or not known_for_block == chr(g)*(g-1):
                            continue #just skip this guess
                    
                    malleated = chr(ord(
                        trial_ct[16*p + 16-i-1]) ^ g ^ (i+1))+malleated
                    
                    mall_ct = trial_ct[:16*p + 16-i-1]+malleated+trial_ct[16*(p+1):16*(p+2)]

                    if validate_aes_cbc_padding(mall_ct):
                        #print 'found char: '+str(g)+' at position: '+str(i)
                        known_for_block = chr(g) + known_for_block
                        found = True
                        break
                if not found:
                    #TODO: there is a final edge case; if the last block
                    #has a single padding byte '\x01' at the end, it won't
                    #have been found. This can easily be checked for here.
                    raise Exception("Failed to find the byte")

            #print 'found block: '+known_for_block
            full_decryption += known_for_block
            #print 'full decryption so far: '+full_decryption

        print 'found full decryption of string '+str(
            k)+' : '+ slowaes.strip_PKCS7_padding(full_decryption)
        fds.append(slowaes.strip_PKCS7_padding(full_decryption))
        print fds
    if fds==ts:
        print 'success'
    else:
        print 'failed'
