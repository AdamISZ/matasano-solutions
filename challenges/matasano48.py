#matasano 6.48

import random
import string
import os
from matasano39 import encrypt, decrypt, inv
from matasano47 import get_small_rsa_key, pkcs1v15_oracle, pkcs1v15_pad_for_encryption
from matasano18 import bi2ba
import binascii


def get_ranges(s, M, B, n):
    #Implementation of Step 3
    M_new = []
    for a,b in M:
        lower_r_bound = int((a*s - 3*B + 1)/n)
        upper_r_bound = int((b*s - 2*B)/n)
        for r in range(lower_r_bound, upper_r_bound+1):
            q, rem = divmod((2*B + r*n), s)
            new_a = q if rem==0 else q+1
            a2 = max([a, new_a])
            b2 = min([b, int((3*B -1 + r*n)/s)])
            if b2 < 3*B -1 and a2 > 2*B and b2 >= a2:
                M_new.append((a2, b2))
    return M_new

bitlength = 768
e = 65537
n, d = get_small_rsa_key(bitlength, e)
msg = "kick it, CC"
pmsg = pkcs1v15_pad_for_encryption(msg, bl=bitlength)
#The ciphertext we are trying to crack:
c = encrypt(n, e, pmsg, bitlength, outfmt='int')

#Bleich. '98 full version
#========================
#Step 1 is skipped as we work with a ciphertext.
B = 2**(bitlength-16)

#Important note: choosing a starting value of n/(3B) as suggested by Bleich.
#yields a result just as fast (faster?) but seems to result
#in a vanishingly small probability of having to execute step
#2b; since multiple ranges only occur if s is large enough to
#multiply the range (2B,3B) into a range spanning more than 
#one modulus wrap. Hence we set it to a much larger value here
#to make that become highly likely, thus "exercising" the 2b
#step and making sure it works.
s = int(5*n/(B))

#the initial range corresponding to 00 02 initial bytes:
M = [(2*B, 3*B-1)]
starting = True
first_only1_range = True
print """Starting the Bleichernbacher '98 attack, note that
it takes anywhere from 30 seconds to several minutes on
my machine, and chews (one) CPU..."""

while True:
    if starting:
        starting = False
        #Step 2a. Find a s1 that is pkcs conformant.
        print "Preparing first s value..."
        while True:
            encs = encrypt(n, e, s, bitlength)
            c1 = c * encs % n
            oracle_check = pkcs1v15_oracle(c1, n, d, bl=bitlength)
            if oracle_check:
                found = True
                break              
            s += 1
    else:
        if len(M)>1:
            #Step 2b
            s += 1
            while True:
                encs = encrypt(n, e, s, bitlength)
                c1 = c * encs % n
                oracle_check = pkcs1v15_oracle(c1, n, d, bl=bitlength)
                if oracle_check:
                    break
                s += 1 
        else:
            #Step 2c   
            #choose an r value, then search for s in the bounds
            #until pkcs found, then recompute M and continue
            found = False
            a, b = M[-1] #guaranteed to be only entry in M
            r = int(2*((b*s - 2*B)/n))-1
            
            while not found:
                r += 1
                for s in range(int((2*B + r*n)/b), int((3*B + r*n)/a)+1):
                    encs = encrypt(n, e, s, bitlength)
                    if pkcs1v15_oracle(c * encs % n, n, d, bl=bitlength):
                        found = True
                        break
                #note that here 's' will be the final successful value
    #Step 3.
    M = get_ranges(s, M, B, n)
    if len(M)>1:
        print "got " + str(len(M)) + " ranges, continuing.."
    else:
        if first_only1_range:
            print "only one range, starting the final narrowing down.."
            first_only1_range = False
    #Step 4
    if len(M)==1 and M[0][0]==M[0][1]:
        print "cracked the message, it's:"
        x =  bi2ba(M[0][0],fixed=bitlength/8)
        print x[1:][x[1:].find('\x00')+1:]
        break
    
    
    
