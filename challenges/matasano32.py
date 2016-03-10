#matasano 4.32

import binascii
import matasano3
from matasano28 import sha1
import os  
import random
import struct
import hmac
import hashlib
import BaseHTTPServer
import SimpleHTTPServer
import time
import threading
from urllib2 import build_opener
import matasano31 as m31
import string

#see comment to st value in challenge 31
#the practical minimum value is now < ~2ms 
#(not sufficiently interested to find the real lower bound)
#instead of ~10ms for the previous version.
st = 0.002

if __name__ == '__main__':
    '''General comment: the tweak is shown below.
    This is not a very pretty way to handle faster delays,
    but I'm not aware of any others; it certainly makes
    the attack pretty slow, and requires a bunch more queries.
    Even with the tweak, this is not remotely close to being
    a practical attack given network timings. How one could
    do such a thing in the real world, I can't imagine... '''
    testk = os.urandom(random.randint(1,32))
    #testk = '1da_'
        
    #start an HTTP server on port 9030 .. etc, same comment as challenge 31.
    m31.secret = testk
    dumb_host = 'localhost'
    dumb_port = 9030
    hostport = (dumb_host, dumb_port)
    m31.HTTPDThread(hostport).start()
    time.sleep(1)
    
    fn = '40degreeday'
    
    #We proceed as if not knowing the secret ... same comment as challenge 31.
    validchars = string.hexdigits[:-6]
    padding = 'a'*40
    known_bytes = ''
    for i in range(40):
        time.sleep(1)
        padding = padding[:-1]
        kbi = known_bytes
        #tweak to #31: first, average time over 5 attempts
        #to smooth out outliers. second, more important:
        #record timing for *all* possible characters
        #and take the slowest, if it's sanely longer than
        #the others (in this case, at least 20% of the time delay)
        chartimes = {}
        for gbi in range(len(validchars)):
            guess_string = known_bytes + validchars[gbi] + padding
            taken = 0.000
            for j in range(3):
                time.sleep(0.02)
                pre_t = time.time()
                res = res = m31.make_request(
                    'http://localhost:9030/test?file='+fn+'&signature='+guess_string)
                taken += time.time() - pre_t
            taken = taken/3.0
            chartimes[validchars[gbi]] = taken
            #print str(taken*1000)
            if res[1]:
                print 'Success, found HMAC digest: '+ guess_string
                exit(0)
        #now we've got a dict of all the timings for the different chars
        #at this position; analyze them relatively, hopefully this will
        #account for drift (along with the averaging above)
        #get the dict keys in order of values
        sorted_chars = sorted(chartimes.items(), key=lambda x: x[1], reverse=True)
        print sorted_chars
        if sorted_chars[0][1] - sorted_chars[1][1] > 0.2 * st:
            print 'char: '+sorted_chars[0][0]+' took: '+str(taken*1000)+' ms.'
            known_bytes += sorted_chars[0][0]
            
        if kbi == known_bytes:
            raise Exception("failed to find any byte in position: "+str(i))
        
                
                
            
            
            