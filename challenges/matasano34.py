#matasano 5.34
 
import random
import binascii
import os
from matasano10 import aes_cbc_decrypt, aes_cbc_encrypt
from matasano28 import sha1
from matasano18 import bi2ba

def netsim(sent, msgtype, MITM_type = None, MITM_data = None):
    '''Trivial wrapper for any data
    sent over the wire, so we can implement MITM
    most logically.
    Note the cases switch_g_to** are for challenge 35.'''
    
    if not MITM_type:
        return sent
    elif MITM_type in ['switch_pubkey_to_p', 'switch_g_to_p']:
        if msgtype == 'enc':
            #decrypt as it passes OTW
            #the key is the sha of zero
            key = binascii.unhexlify(sha1(bi2ba(0)))[:16]
            decrypted = aes_cbc_decrypt(sent, key)
            print 'Mallory saw: ' + decrypted
            return sent
        else:
            #swap out the data
            return MITM_data
    elif MITM_type == 'switch_g_to_1':
        if msgtype == 'enc':
            #decrypt as it passes OTW
            #the key is the sha of 1, since 1^(ab)=1
            key = binascii.unhexlify(sha1(bi2ba(1)))[:16]
            decrypted = aes_cbc_decrypt(sent, key)
            print 'Mallory saw: ' + decrypted
            return sent
        else:
            #swap out g for 1
            return MITM_data        
    elif MITM_type == 'switch_g_to_p-1':
            if msgtype == 'enc':
                #decrypt as it passes OTW
                #the key is the sha of 1 or -1, since (p-1)^x modp = +/-1
                key = binascii.unhexlify(sha1(bi2ba(1)))[:16]
                try:
                    decrypted = aes_cbc_decrypt(sent, key)
                except ValueError:
                    key = binascii.unhexlify(sha1(bi2ba(MITM_data)))[:16]
                    decrypted = aes_cbc_decrypt(sent, key)
                print 'Mallory saw: ' + decrypted
                return sent
            else:
                #swap out g for p-1
                return MITM_data            
    else:
        raise NotImplementedError
    
if __name__ == '__main__':
    '''Also fairly trivial; will reuse p/g.
    Just replace received pubkey with p.
    Simulate passing OTW with a function, any
    MITM stuff injected there.'''
    
    g = 2
    pstr = """
    ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
    e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
    3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
    6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
    24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
    c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
    bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
    fffffffffffff
    """
    p = long(eval('0x'+''.join(pstr.split())))
    #run through the process twice, once with and once
    #without the MITM; in the latter case, check that
    #Mallory can decrypt.
    for mitm in [(None, None),('switch_pubkey_to_p', p)]:
        #A makes new keypair (a,A) and sends p,g,A to B
        a = random.randint(0,p-1)
        A = pow(g, a, p)
        
        pB = netsim(p, 'key-exchange')
        gB = netsim(g, 'key-exchange')
        AB = netsim(A, 'key-exchange', mitm[0], mitm[1]) #MITM sends p instead of A
        
        #B makes new keypair (b, B) and sends B to A
        b = random.randint(0, p-1)
        B = pow(gB, b, pB)
        
        BA = netsim(B, 'key-exchange', mitm[0], mitm[1]) #MITM sends p instead of B
        
        #A calculates the shared secret s and uses its
        #hash as a key for sending an AES-CBC encrypted message to B
        s = pow(BA, a, p)
        key_A = binascii.unhexlify(sha1(bi2ba(s)))[:16]
        iv_A = os.urandom(16)
        sent_to_B = netsim(aes_cbc_encrypt("This is A for sure", key_A, iv_A), 
                           'enc', MITM_type=mitm[0])
        
        #B calculates his version of key, reads message
        s2 = pow(AB, b, pB)
        key_B = binascii.unhexlify(sha1(bi2ba(s2)))[:16]
        received_by_B = aes_cbc_decrypt(sent_to_B, key_B)
        print 'B received: ' + received_by_B
        
        #B sends something to A, same story
        iv_B = os.urandom(16)
        sent_to_A = netsim(aes_cbc_encrypt("This is B for sure", key_B, iv_B),
                           'enc', MITM_type=mitm[0])
        received_by_A = aes_cbc_decrypt(sent_to_A, key_A)
        print 'A received: '+ received_by_A
    
        print 'OK for case : '
        print mitm

            