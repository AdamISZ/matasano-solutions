#matasano 6.45

import random
import string
from hashlib import sha1
from matasano39 import inv
from matasano18 import bi2ba
import binascii
from itertools import combinations
import matasano43

#messing around with 'g':

#First section is commented out, because our implementation
#of verification, like any proper one, will not allow r=0 or s=0
#as part of the signature; it will just loop infinitely
#looking for a nonce that generates a non-zero r, and
#never find it.

#matasano43.g = 0
#message = "hello world"
#privkey = matasano43.get_random_key()
#print matasano43.sign(message, privkey)

#Next, we try making a signature with g=1 for some random key.
#We notice we can make a signature that verifies against any message
#this way.
real_g = matasano43.g
matasano43.g = matasano43.p+1
message = "Goodbye cruel world"
privkey = matasano43.get_random_key()
sig = matasano43.sign(message, privkey)
print sig
pubkey = matasano43.privtopub(privkey)
#Demonstrate verification with correct parameters:
print "verifying sig against correct message with g=1, result:"
print matasano43.verify(message, sig, pubkey)
#Demonstrate verification against the wrong message:
print "verifying sig against wrong message with g=1, result:"
print matasano43.verify("Hello that same world", sig, pubkey)

#Last, show that even if we don't know the privkey, we can
#forge a signature if g=1 mod p.

#The formula given in the challenge can be verified
#to work in cases where the pubkey y is known, and g can be coerced into 1 mod p.
#Consider that if r = y^z, and s = r*z^-1, where y is the pubkey and z is any 
#number, and our calculations use g=1, then:
# s = z^-1 * (y^z)
# w = s^-1 = z * (y^z)^-1
# u1 is irrelevant, since g^u1 is just 1; note that since the message
# only affects u1, the forged signature will work for *any* message.
# u2 = r * w = (y^z) * z * (y^z)^-1 = z (<-- this is the key point, cancelling)
# v = (1 * y^u2) = (1 * y^z) = y^z = r. QED.


#temporarily reset the correct 'g' to get a real pubkey
#(or just choose a random number < p)
matasano43.g = real_g
pubkey = matasano43.privtopub(matasano43.get_random_key())
#set it back to p+1
matasano43.g = matasano43.p + 1
#choose a random value for z
z = matasano43.get_random_key()
z_inv = inv(z, matasano43.q)
fake_r = pow(pubkey, z, matasano43.p) % matasano43.q
fake_s = (fake_r * z_inv) % matasano43.q
#some stupid messages
msgs = [''.join([random.choice(string.letters) for _ in range(
    random.randint(5,50))]) for _ in range(10)]
msgs = ["Hello, world", "Goodbye, world"] + msgs
for msg in msgs:
    res = matasano43.verify(msg, (fake_r, fake_s), pubkey)
    if not res:
        print "sig verification failed"
        exit()
    print "Forged signature for message: " + msg + " with g=1, successful."
print "successfully forged all sigs"

