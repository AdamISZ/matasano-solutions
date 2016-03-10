#matasano 5.40
 
import binascii
import os
from matasano18 import bi2ba
from matasano39 import inv, make_keypair
from Crypto.PublicKey import RSA

trial_text = "Why I myself am quite a tolerable practical magician."

#one of a few root implementations i found on the web.
def iroot(k, n):
    '''Computes n^(1/k)'''
    u, s = n, n+1
    while u < s:
        s = u
        t = (k-1) * s + n // pow(s, k-1)
        u = t // k
    return s

if __name__ == '__main__':
    '''e=3 RSA broadcast attack using CRT.
    NOTE: the instructions on cryptopals appear to be wrong.
    You *DO* have to find the result MODULO the product of the moduli,
    *BEFORE* taking the e-th root. See a detailed example here:
    http://www.di-mgt.com.au/crt.html
    '''
    bitlength = 2048 # must be power of 2
    e = 3
    trial_text_int = int(eval('0x'+binascii.hexlify(trial_text)))
    
    #generate pubkeys (means moduli, since all keys use e=3)
    moduli = []
    mod_product = 1
    for i in range(e):
        n, d = make_keypair(bitlength, e)
        moduli.append(n)
        mod_product *= n
        #don't bother to keep the private key, we won't use it
        
    #get the encryptions of the fixed plaintext w.r.t. the pubkeys
    ciphertexts = []
    for i in range(e):
        ciphertexts.append(pow(trial_text_int, e, moduli[i]))
    
    #do CRT 
    result = 0
    for i in range(e):
        temp = ciphertexts[i]
        m_s = 1
        for j in [x for x in range(3) if x != i]:
            m_s *= moduli[j]
        temp *= (m_s * inv(m_s, moduli[i]))
        result += temp
    result = int(result) % mod_product
    result = iroot(3, result)
    print 'cracked message: '+bi2ba(result, fixed=bitlength/8)
