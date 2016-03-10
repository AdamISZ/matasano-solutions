#matasano 3.24

import base64
import binascii
import matasano21
import matasano3
import random
import time
import os

def crypt(keystream, pt): 
    #elementary xor stream cipher, given keystream
    ct = matasano3.xor(keystream[:len(pt)], map(ord, pt), fmt='ord')
    return binascii.unhexlify(ct)    

def get_keystream(plaintext, seed):
    matasano21.seed_mt(seed)    
    keystream_ints = []
    keystream = []
    for i in range(len(plaintext)/4 + 1):
        keystream_ints.append(matasano21.extract_number())
    for ksi in keystream_ints:
        x = matasano21.int_to_bitarray(ksi)
        keystream.extend([matasano21.bitarray_to_int(
            x[i:i+8]) for i in range(0,len(x), 8)])
    return keystream[:len(plaintext)]

if __name__ == '__main__':
    '''Step 1:
    Write the function that does this for MT19937 using a 16-bit seed. 
    Verify that you can encrypt and decrypt properly. 
    This code should look similar to your CTR code. '''
    seed = random.randint(1,2**16-1)
    seed = 2**16 - 2**15 +79    
    plaintext = 'ATTACK AT DAWN'
    encrypted = crypt(get_keystream(plaintext, seed), plaintext)
    print binascii.hexlify(encrypted)
    if not crypt(get_keystream(plaintext, seed), encrypted)==plaintext:
        raise Exception("Encrypt decrypt failed")
    
    '''Step 2:
     Use your function to encrypt a known plaintext (say, 14 consecutive 'A' 
     characters) prefixed by a random number of random characters.
     From the ciphertext, recover the "key" (the 16 bit seed). 
    '''
    prepend = os.urandom(random.randint(1,16))
    plaintext = prepend + 'A'*14
    #Brute force is enough to crack a 16 bit seed
    #(Isn't this a bit dumb? Nothing to do with MT?)
    
    #Initialize keysream with to-be-cracked seed
    secret_seed = random.randint(1,2**16-1)
    print 'using secret seed: ' + str(secret_seed)
    #Encrypt
    secret_keystream = get_keystream(plaintext, secret_seed)
    encrypted = crypt(secret_keystream, plaintext)
    #use knowledge that last 14 chars are all 'A' to get 
    #the last 14 bytes of keystream
    cksb = []
    for i in range(len(encrypted)-14,len(encrypted)):
        cksb.append(matasano3.xor(encrypted[i],'A', fmt='bin'))

    #Bruteforce step; recreate keystream for every possible seed
    for i in range(2**16):
        if not i%1000:
            print 'on seed: '+str(i)
        ks = get_keystream(plaintext, i)
        if [binascii.hexlify(chr(_)) for _ in ks[-len(cksb):]]==cksb:
            print 'cracked; key is: '+str(i)
            break
    '''
     Use the same idea to generate a random "password reset token" 
     using MT19937 seeded from the current time.
     Write a function to check if any given password token is actually
     the product of an MT19937 PRNG seeded with the current time.
'''
    #This is pretty ill-defined? I'll make a string of 10 bytes
    #and base64 encode them, by seeding MT with the current time
    #and then taking the first 3 integers from the stream.
    #Then, I'll use current unix time - [0..10] seconds, reseed and compare.
    #This also seems entirely uninteresting?
    seed = int(time.time()) #32 bit integer
    
    token = base64.b64encode(''.join(
        [chr(_) for _ in get_keystream('x'*10, seed)]))
    
    print 'password token: '+token
    
    #cracking
    newtime = int(time.time())
    #Idea here is to put in the token we just created; just an example of course.
    given = raw_input("Enter password token: ")
    for i in range(100):
        guess_time = newtime-i
        if given == base64.b64encode(''.join(
            [chr(_) for _ in get_keystream('x'*10, guess_time)])):
            print 'yes, this is a token seeded from MT with time: '+str(guess_time)
            exit(0)
    print 'Did not find that token, failed.'
            
        
    
    

