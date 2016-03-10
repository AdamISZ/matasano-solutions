#matasano 2.14

import slowaes
import base64
import binascii
import matasano3
import matasano7
import matasano10
import matasano12
import os
import random

def ecb_modified_2(s):
    rand_len = random.randint(1,32)
    rand_prepend = os.urandom(rand_len)
    #for debugging (not cheating!)
    #print 'using randomised prepend: '+binascii.hexlify(rand_prepend)
    return rand_prepend, matasano12.ecb_modified(rand_prepend+s)

if __name__ == '__main__':
    bs = 16
    known_txt = ''
    while len(known_txt)<100:
        print "**KNOWN TXT IS NOW: "+known_txt
        for c in matasano3.x:
            ktl = len(known_txt)
            #construct the attack string as followed:
            #'B' + two blocks of repeated string: 'A'*32 NOTE: it must
            #be different from the first char of the next block
            #then, next block of repeated char c + knowntxt +one char c at end
            #then 4th incomplete block: repeated char c + knowntxt (15)
            #repeat enc calls until first two blocks repeat: this tells us the
            #block alignment is right. Then, check the next two blocks; if they
            #match, 'c' is the right char.
            #
            #For a known text > 16 bytes, we need to expand out the attack
            #segment so that 'c' occupies the final byte of the Nth attack
            #block, where N is knowntextlength/16 + 1
            #can work it out on paper; the general formula for the attack string
            #is: (16 - ktl%16 -1) x 'c' + known text + (16 - ktl%16) x 'c'
            
            #initial padding for detection; don't use 'A'/'B', but bytes
            #definitely different from c.
            attack_string = chr(ord(c)+2)
            attack_string += chr(ord(c)+1)*bs*2
            
            #known text detection section
            attack_string += c*(bs - ktl%bs -1)
            attack_string += known_txt
            attack_string += c*(bs - ktl%bs)
            
            #print 'starting with attack string: '+attack_string
            found = False
            for i in range(24):
                #find a repeated block of all 'A', at least
                blocks = matasano3.get_blocks(ecb_modified_2(attack_string)[1])
                #get the index position of the FIRST REPEATED PAIR of blocks (all A)
                repeated_blocks = list(set([x for x in blocks if blocks.count(x)>1]))
                #repeated block indices
                rbi = [blocks.index(_) for _ in repeated_blocks]
                try:
                    first_repeat_index = min(rbi)
                except ValueError:
                    continue
                #the number of repeated blocks is:
                #2 pairs if known text length < 16
                #3 pairs if ... 16<=ktl<32
                #4 pairs if 32<=ktl<48
                #etc
                pairs_expected = 2+(ktl/16)
                if len(rbi)==pairs_expected:
                    found = True
                    #print 'first pair of repeated blocks was: '
                    #print binascii.hexlify(''.join([''.join(_) for _ in blocks]))
                    print "found char: "+str(c)
                    known_txt += c
                    break
            if found:
                break
