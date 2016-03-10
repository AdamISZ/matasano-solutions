#matasano 3.20

import slowaes
import base64
import binascii
import matasano12
import matasano18
import matasano6
import os    

if __name__ == '__main__':
    #The concept of this challenge is that with a fixed nonce,
    #the keystream for each encryption is fixed, meaning we have the
    #same secret key for the xor operation (ciphertext = keystream ^ plaintext)
    #for each ciphertext (assuming fixed length, see below re: truncation)
    #Thus we borrow the process of Challenge 6, but we can skip the first
    #step of finding the likely key length via the hamming distance, because
    #we already know it.    
    with open('20.txt', 'rb') as f:
        txt64 = f.read()
    #print txt64
    txt64 = txt64.split('\n')[:-1]
    bs = 16
    k = matasano12.fixed_k
    txt = [base64.b64decode(_) for _ in txt64]
    print txt #for comparison
    #encrypt in aes-ctr mode with the new random key, but using a zero nonce
    #note that it's a separate encryption for *each* text
    ciphertexts = [matasano18.aes_ctr_crypt(_, k, 0) for _ in txt]
    
    #for debugging: with key = matasano12.fixed_k, keystream for first 53 bytes is:
    #ea9bd792c6ce179c3106113d88d5410a7bdcae72c50235db5b48cdf6b733de4d712c975b3fb3bce82b257a80cfab046692d782373f

    #truncate according to instructions
    tlength = min([len(_) for _ in ciphertexts])
    ciphertexts = [c[:tlength] for c in ciphertexts]
    decrypted = matasano6.decrypt_from_keysize(tlength, ''.join(ciphertexts))
    dec_list = [decrypted[i:i+tlength] for i in range(0, 
                                                      tlength*len(ciphertexts),
                                                      tlength)]
    print dec_list
    if [x[:tlength] for x in txt] == [y[:tlength] for y in dec_list]:
        print 'Unqualified victory!'
    else:
        print 'not quite success?'
        print list(
            set([x[:tlength] for x in txt])-set([y[:tlength] for y in dec_list]))

    
    
