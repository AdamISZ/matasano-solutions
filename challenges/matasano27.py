#matasano 4.27
import binascii
import matasano3
import matasano16
import matasano18
import os  
import random


if __name__ == '__main__':
    bs = 16
    #add in any data to the url creator inside aes_cbc_modified
    istring = 'A'*random.randint(5,16)
    k1 = os.urandom(16)
    ct = matasano16.aes_cbc_modified(istring, k=k1, iv=k1)
    print binascii.hexlify(ct)
    
    #construct a modified ciphertext.
    #note: this seems very artificial, because
    #the ciphertext provided to my aes-cbc decrypt function
    #must have the IV as its first block; but, one could 
    #imagine a scenario where, if the code is using the IV as the key,
    #would have to be implicit (it can't be passed over the wire!)
    #In that situation, we would obviously not be passing 'k1' as the first
    #block to aes_cbc_decrypt!
    ct1 = ct[16:32]
    ct2 = '\x00'*16
    ct3 = ct1
    ct4 = ct[64:]
    res = matasano16.aes_cbc_decrypt_to_object(k1+ct1+ct2+ct3+ct4, k=k1, highasciicheck=True)
    if res.startswith('Non ascii string: '):
        recovered = res[len('Non ascii string: '):]
        key = matasano3.xor(recovered[:16], recovered[32:48], fmt='bin')
        if key == binascii.hexlify(k1):
            print 'succes, key cracked'
        else:
            print 'failed to crack key'
    else:
        'no non ascii found'
        
    '''
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
        
    '''