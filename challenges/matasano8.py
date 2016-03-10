#matasano 1.8

import slowaes
import base64
import binascii
import collections
import matasano3

block_size = 16
with open('8.txt','rb') as f:
    hexlines = f.readlines()
#print 'hexlines was: '
#print hexlines

binlines = [binascii.unhexlify(_.strip()) for _ in hexlines]

biggest_so_far = -1
for i, bl in enumerate(binlines):
    blocks = matasano3.get_blocks(bl, block_size)
    if len(blocks) != len(set(blocks)):
        print 'got index: '+str(i)
        print 'got data: '+hexlines[i]
        print 'blocks were: '+'\n'.join([binascii.hexlify(''.join(_)) for _ in blocks])
        exit(0)
    
print 'failed'