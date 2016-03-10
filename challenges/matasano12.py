#matasano 2.12

import slowaes
import base64
import binascii
import collections
import matasano3
import matasano7
import matasano10
import os
import random

fixed_k = 'dead'*4

target_bytes = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9'+
                                   'wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2ly'+
                                   'bGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNhe'+
                                   'SBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdm'+
                                   'UgYnkK')

def ecb_modified(txt, k=None):
    if not k:
        k = fixed_k
    bs = 16
    new_txt = txt + target_bytes
    return matasano7.ecb_encrypt(new_txt, k, bs)
    

def get_one_byte(known_txt, bs):
    #algo:
    #if ktlen = 0, use bs-1 * 'A', find last byte of 1st block that matches *JUST* using bs-1*'A' as input
    #1, use bs-2 *'A'+kt[1 char], find last ;; ;;
    #2, use bs-3 * 'A'+kt[2char], find last ;; ;;
    #..
    #15, use bs-16=0*'a' +kt[15char], find last ;; ;;
    #then wrap around:
    #16, use bs-1*'A'+kt[16char], find last byte of 2nd block
    #17, use bs-2*'A'+kt[17char], find last ;; ;;
    #etc
    allchars = matasano3.x
    set1 = {}
    ktlen = len(known_txt)
    prepad = 'A'*(bs - ktlen%bs - 1)
    blockstart, rem = divmod(ktlen, bs)
    start = blockstart*bs
    for c in range(128):
        txt = prepad+known_txt+chr(c)
        #print 'trying tweaked string: '+txt
        set1[chr(c)] = ecb_modified(txt)[start:start+bs]
    real_block = ecb_modified(prepad)[start:start+bs]
    return set1.keys()[set1.values().index(real_block)]

if __name__ == '__main__':
    #detect the block cipher size
    bsfound = 0
    for i in range(1,34):
        trial = 'A'*(i+1)
        encrypted = ecb_modified(trial)
        if not i%2: #even
            if encrypted[:i/2]==encrypted[i/2:i]:
                print 'found block size: '+str(i)
                bsfound = i/2
                break
    if not bsfound:
        print 'failed to find block size'
        exit(0)
    #try nasty text
    nasty_text = 'YELLOW SUBMARINE'*20
    encrypted = ecb_modified(nasty_text)
    blocks = matasano3.get_blocks(encrypted, bsfound)
    if len(blocks) != len(set(blocks)):
        print 'ECB detected, OK'
    else:
        print 'not ECB?'
        exit(0)
    known = ''
    for i in range(100):
        bt = get_one_byte(known, bsfound)
        known += bt
        print 'known so far: '+known
        
''' Decrypt:
Rollin' in my 5.0
With my rag-top down so my hair can blow
The girlies on standby waving just to say
(etc etc)'''