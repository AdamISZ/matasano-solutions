#matasano 2.11

import slowaes
import base64
import binascii
import collections
import matasano3
import matasano7
import matasano10
import os
import random

def randomK(n):
    return os.urandom(n)

#function that replicates real world behaviour a 
#bit by adding some prepend and append random bytes
#to your controlled txt input, and then encrypts 
#with either ECB or CBC with 50% probability.
def ecb_cbc_oracle(txt, bs):
    btab = random.randint(5,10)
    btaa = random.randint(5,10)
    ab = os.urandom(btab)
    aa = os.urandom(btaa)
    new_txt = ab + txt + aa
    k = randomK(bs)
    if random.randint(0,1):
        #print 'cheat, was: CBC'
        iv = os.urandom(bs)
        return matasano10.aes_cbc_encrypt(new_txt, k, iv, bs)
    else:
        #print 'cheat, was ECB'
        return matasano7.ecb_encrypt(new_txt, k, bs)
    
    
if __name__ == '__main__':
    block_size = 16
    while True:
        print 'doing a run'
        raw_input()
        #choose some nasty text
        txt = "YELLOW SUBMARINE"*20
        output = ecb_cbc_oracle(txt, block_size)
        #check for repeats in the blocks
        blocks = matasano3.get_blocks(output, block_size)
        if len(blocks) != len(set(blocks)):
            print 'was ECB'
        else:
            print 'was CBC'

