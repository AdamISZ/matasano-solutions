#matasano 3.22

import binascii
import matasano21
import random
import time


if __name__ == '__main__':
    #unix timestamp is 32 bit integer number of **seconds**
    first = True
    previous_seed = None
    while True:
        seed = int(time.time())
        matasano21.seed_mt(seed)
        current_rand = matasano21.extract_number()
        print 'for time: '+str(seed)+' got rand: '+str(current_rand)
        
        #do some shenanigans to get the seed; we know that it must a the Unix time
        #between <last time's seed> and <now>
        if not first:
            if not previous_seed:
                previous_seed = int(time.time())-20
            for i in range(previous_seed, int(time.time())):
                matasano21.seed_mt(i)
                if matasano21.extract_number()==last_rand:
                    print 'success, cracked seed: '+str(i)
                previous_seed = i
            if not previous_seed:
                raise Exception("Failed to crack the seed")                
        else:
            first = False    
        last_rand = current_rand
        sleeptime = random.randint(5,100)
        print 'now sleeping for time: '+str(sleeptime)+' seconds.'
        time.sleep(sleeptime)

