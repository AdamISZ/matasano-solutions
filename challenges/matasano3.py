import binascii
import string
import sys

def get_blocks(txt, block_size=16):
    return map(None,*([iter(txt)]*block_size))

def xor(a,b, fmt='hex'):
    if fmt=='ord':
        a, b = [''.join(map(chr, _)) for _ in [a,b]]
    elif fmt=='hex':
        a = a.decode('hex')
        b = b.decode('hex')
    elif fmt != 'bin':
        raise Exception('Invalid input format')
    return binascii.hexlify(bytearray([ord(a) ^ ord(b) for a,b in zip(a,b)]))

trial_ciphertext = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

scores = {}
x = string.digits + string.whitespace + string.ascii_letters + '\'' + '.' + ','+'!'+'-'+'/'
def find_key(ciphertext=trial_ciphertext):
    for k in [chr(_) for _ in range(256)]:
        scores[k]=0
        keystring = k *len(ciphertext)
        plaintext = xor(binascii.hexlify(keystring),ciphertext).decode('hex')
        for p in plaintext:
            if p in x:
                scores[k] += 1
    
    best = sorted(scores,key=scores.get, reverse=True)[0]
    
    score = scores[best]
    result = xor(binascii.hexlify(best*len(ciphertext)),ciphertext).decode('hex')
    #print ("The most likely key is: ", best, 
    #       'with plaintext:', result)
    
    return (best,result,score)
    
if __name__ == "__main__":
    print find_key()