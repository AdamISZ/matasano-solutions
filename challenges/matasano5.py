import matasano3
import binascii
trial_plaintext = 'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'

ciphertext = ''
keystring='ICE'

def build_keystring(seed, plaintext):
    quot, rem = divmod(len(plaintext), len(seed))
    return seed * quot + seed[0:rem]

print matasano3.xor(
    binascii.hexlify(build_keystring(keystring,trial_plaintext)),
    binascii.hexlify(trial_plaintext))
    