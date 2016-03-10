#matasano 6.41
 
import binascii
import os
import random
from matasano18 import bi2ba
from matasano39 import inv, make_keypair, encrypt, decrypt
from Crypto.PublicKey import RSA

trial_text = "Why I myself am quite a tolerable practical magician."

if __name__ == '__main__':
    '''Attack on textbook RSA. This is a very easy one.
    '''
    bitlength = 2048 # must be power of 2
    e = 3
    server_mod, server_d = make_keypair(bitlength, e)
    external_ciphertext = encrypt(server_mod, e, trial_text, outfmt='int')
    blinding_rand = random.randint(1000, server_mod)
    print 'using blinding rand: '+str(blinding_rand)
    fake_ciphertext = encrypt(server_mod, e, blinding_rand)
    blinded_ciphertext = (fake_ciphertext * external_ciphertext) % server_mod
    #send the blinded ciphertext to the server; it will return its decryption:
    decryped_from_server = decrypt(server_mod, server_d, blinded_ciphertext,
                                   outfmt='int')
    #divide by blinding_rand
    orig_plaintext = (decryped_from_server * inv(blinding_rand,
                                                 server_mod)) % server_mod
    print 'Retrieved original plaintext: ' + str(bi2ba(
        orig_plaintext, fixed=bitlength/8))
    