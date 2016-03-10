#matasano 6.44

import random
from hashlib import sha1
from matasano39 import inv
from matasano18 import bi2ba
import binascii
from itertools import combinations
from matasano43 import sign, verify, privtopub, \
     recover_privkey_from_nonce, m2int, g, p, q

given_pubkey = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821

def get_common_nonce(m1, m2, sig1, sig2):
    '''If two messages were signed with the same
    nonce, this will return that nonce. Sigs must be
    passed in format (r,s) (integers)'''
    r1, s1 = sig1
    r2, s2 = sig2
    m1 = m2int(m1)
    m2 = m2int(m2)
    sdiff_inv = inv((s1 - s2)%q, q)
    return (((m1 - m2)%q) * sdiff_inv) % q

#Load the signature data from the textfile.
#A bit kludgy but w/e.
sig_data = []
with open('44.txt', 'rb') as f:
    sig_data_lines = f.readlines()
#Remove trailing newlines
sig_data_lines = [_.rstrip('\n') for _ in sig_data_lines]
for i in range(len(sig_data_lines)/4):
    start = i*4
    msg = sig_data_lines[start][5:]
    s = int(sig_data_lines[start+1][3:])
    r = int(sig_data_lines[start+2][3:])
    m = sig_data_lines[start+3][3:]
    if len(m)%2:
        m = '0'+m
    if sha1(msg).hexdigest() != m:
        print msg
        print m
        print sha1(msg).hexdigest()
        raise Exception("Wrong hash")
    sig_data.append((msg, s, r, m))

#Now we have the data loaded, the strategy is:
#Take each pair of signature data structures, and assume
#they used the same nonce; recover it with the formula.
#Then, use the privkey-recovery-from-nonce algo on 
#one, and see if it generates the given pubkey. If so, it's the right
#privkey, and check the fingerprint.
for x in combinations(sig_data, 2):
    sd1, sd2 = x
    
    #calculate "hoped for" k value (if it was the same)
    guessed_k = get_common_nonce(sd1[0], sd2[0], (sd1[2], sd1[1]), (sd2[2], sd2[1]))
    guessed_privkey = recover_privkey_from_nonce(sd1[0], (sd1[2], sd1[1]), guessed_k)
    if privtopub(guessed_privkey) == given_pubkey:
        print "found privkey, it is: " + str(guessed_privkey)
        if not sha1(hex(guessed_privkey)[2:-1]).hexdigest() == "ca8f6f7c66fa362d40760d135b763eb8527d3d52":
            print "oops, didn't match fingerprint"
        else:
            print "and it matched the given fingerprint, done."
            exit(0)

#Hmm, that worked immediately. Thatescalatedquicky.jpg    
