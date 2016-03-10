#matasano 4.29

import binascii
import matasano3
from matasano28 import keyed_sha1, sha1
import os  
import random
import struct

def compute_padding_for_msg(msglen):
    '''Just copied from the sha1 implementation
    in matasano28.py (trivial edit)'''
    # append the bit '1' to the message
    pad = b'\x80'
    # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
    # is congruent to 56 (mod 64)
    pad += b'\x00' * ((56 - (msglen + 1) % 64) % 64)
    message_bit_length = msglen * 8
    pad += struct.pack(b'>Q', message_bit_length)    
    return pad

if __name__ == '__main__':
    testmsg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    testk = os.urandom(random.randint(1,32))
    first_digest = keyed_sha1(testmsg, testk)
    print 'keyed sha: '+ first_digest
    print 'padding is: '+binascii.hexlify(compute_padding_for_msg(len(testk+testmsg)))
    print '\n'
    want_to_forge = ';admin=true'

    #range over reasonable key sizes. so fast, the number doesn't matter.
    #In a real life attack, it wouldn't be so fast, since you might
    #have to ping your 'sha1 keyed mac oracle server' to find out if
    #you have the right number (on the other hand, guessing a key size
    #is not the *most* difficult problem...)
    for klg in range(40): 
        #calculate the exact padding bytes there would have been if
        #this was the correct key length
        pad = compute_padding_for_msg(klg + len(testmsg))
        
        #Extract the 5 h values from the digest (this is the state vector for the hash fn)
        cracks = [int(first_digest[i:i+8],16) for i in range(0,len(first_digest),8)]
        #when forging we also need to pass the length of the message *including*
        #the 'glue padding', i.e. the padding bytes from the previous unforged message.
        forge_output = sha1(want_to_forge, cracks, pml=klg + len(testmsg) + len(pad))
        
        real_output = keyed_sha1(testmsg + pad + want_to_forge, testk)
        
        if real_output == forge_output:
            print '**Success!'
            print 'Key length was: '+str(klg)
            print 'We forged a keyed hash for this message: '
            print testmsg + pad + want_to_forge
            print '.. without knowing the key. The hash was: '
            print real_output
            exit(0)
    print 'failed!'
        
    
    
    
