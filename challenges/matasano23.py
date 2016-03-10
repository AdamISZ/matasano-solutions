#matasano 3.23

import binascii
import matasano21
import random
import time


if __name__ == '__main__':
    '''The difficult part of this challenge
    is to implement the untemper function; see
    the code in matasano21.py for this.
    Once that is in place, it is trivial to
    recover the intermediate state and predict
    future outputs, as seen below.'''
    matasano21.seed_mt(random.randint(1,2**32-1))
    untempered = []
    for i in range(matasano21.n):
        yout = matasano21.extract_number()
        untempered.append(matasano21.untemper(yout))
    
    #choose a number of outputs to predict:
    pred = random.randint(1,1000)
    #generate the next pred outputs of the original twister:
    generated = [matasano21.extract_number() for i in range(pred)]
    #to get the cloned versions, need to set MT[] to untempered and reset 
    #the pointer to the right position
    matasano21.ptr = matasano21.n
    matasano21.MT = untempered
    cloned = [matasano21.extract_number() for i in range(pred)]
    print generated == cloned
