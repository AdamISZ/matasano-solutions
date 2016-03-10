#matasano 4.31

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
import string

#the artificial delay per byte
#in the insecure string comparison function.
#The attack in simple form works down to ~10ms,
#but is unreliable for lower values.
#Obviously, this is highly implementation-depedent!
st = 0.01

#The secret key declared as global, as accessed by the 
#server but also the main code (for debugging/checking)
secret = None

def insecure_compare(txt1, txt2):
    if len(txt1) != len(txt2):
        return False
    for i in range(len(txt1)):
        time.sleep(st)
        if txt1[i] != txt2[i]:
            return False
    return True

def make_request(*args):
    '''Second element of returned tuple
    is for convenience of caller knowing whether
    call was successful in returning data or not.'''
    opener = build_opener()
    opener.addheaders = [('User-agent',
                          'Mozilla/5.0' + str(random.randrange(1000000)))]
    try:
        return (opener.open(*args).read().strip(), True)
    except Exception as e:
        try:
            p = e.read().strip()
        except:
            p = repr(e)
        return (e, False)

class DumbRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    
    def __init__(self, request, client_address, base_server):
        self.base_server = base_server
        SimpleHTTPServer.SimpleHTTPRequestHandler.__init__(
                self, request, client_address, base_server)

    def do_GET(self):

        if self.path.startswith('/test?'):
            querystring = self.path[len('/test?'):]
            queryfields = querystring.split('&')
            querydict = {}
            for q in queryfields:
                if q.count('=') != 1:
                    self.send_response(500)
                    break
                querydict[q.split('=')[0]]= q.split('=')[1]

            if set(querydict.keys()) != set(['file', 'signature']):
                self.send_response(500)
                self.end_headers()
                self.wfile.write('Invalid query')
                return
            correct_hmac = hmac1(secret, querydict['file'])
            if not insecure_compare(correct_hmac, querydict['signature']):
                self.send_response(500)
                self.end_headers()
                self.wfile.write('Invalid HMAC')
                return
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write('Success - access granted.')
        else:
            self.send_response(500)
            self.end_headers()
            self.wfile.write('Invalid URL')

        self.end_headers()
    

'''HMAC pseudocode from Wikipedia:
function hmac (key, message)
    if (length(key) > blocksize) then
        key = hash(key) // keys longer than blocksize are shortened
    end if
    if (length(key) < blocksize) then
        key = key + [0x00 * (blocksize - length(key))] // keys shorter than blocksize are zero-padded
    end if
   
    o_key_pad = [0x5c * blocksize] ^ key // Where blocksize is that of the underlying hash function
    i_key_pad = [0x36 * blocksize] ^ key 
   
    return hash(o_key_pad + hash(i_key_pad + message))
end function
'''

def hmac1(key, message, algo='SHA-1'):
    if algo != 'SHA-1':
        raise NotImplementedError
    if algo in ['SHA-1', 'MD5', 'RIPEMD-128', 'RIPEMD-160']:
        bs = 64
    else:
        raise NotImplementedError
    if len(key)> bs:
        key = sha1(key)
    if len(key) < bs:
        key += '\x00'*(bs-len(key))
    o_key_pad = binascii.unhexlify(matasano3.xor('\x5c'*bs, key, fmt='bin'))
    i_key_pad = binascii.unhexlify(matasano3.xor('\x36'*bs, key, fmt='bin'))
    return sha1(o_key_pad + binascii.unhexlify(sha1(i_key_pad + message)))

class HTTPDThread(threading.Thread):
    def __init__(self, hostport):
        threading.Thread.__init__(self)
        self.daemon = True
        self.hostport = hostport

    def run(self):
        httpd = BaseHTTPServer.HTTPServer(self.hostport,
                                          DumbRequestHandler)
        print('\nstarted http server, visit http://{0}:{1}/\n'.format(
                *self.hostport))
        httpd.serve_forever()

if __name__ == '__main__':
    testmsg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    testk = os.urandom(random.randint(1,32))
    
    #sanity check our HMAC impl. against the Python default
    if not hmac.new(testk, testmsg, hashlib.sha1).hexdigest() == hmac1(testk, testmsg):
        print 'HMAC not correctly implemented'
        exit(0)
        
    #start an HTTP server on port 9030 that returns 200 OK
    #if the field in the query url 'file' has the same HMAC
    #given in the 'signature' field as the one locally calculated
    #using the secret key. Put a delay (global var 'st') per byte of comparison
    #of presented HMAC with calculated one to simulate slow calculation.
    #global secret
    secret = testk
    dumb_host = 'localhost'
    dumb_port = 9030
    hostport = (dumb_host, dumb_port)
    HTTPDThread(hostport).start()
    time.sleep(1)
    
    fn = '40degreeday'
    
    '''For sanity testing
    x = random.randint(1,10)
    if x < 5:
        signature = hmac1(secret, fn)
    else:
        signature = binascii.hexlify(os.urandom(random.randint(4, 25)))
    res = make_request('http://localhost:9030/test?file='+fn+'&signature='+signature)
    if not res[1]:
        print 'That was a 500, error: '+str(res[0])
    else:
        print 'That was a 200, all OK'
    '''
    
    #We proceed as if not knowing the secret, but only
    #wanting to find a valid HMAC for filename 'fn':
    #We know that the time taken is a linear function of the number
    #of correct bytes in the guessed HMAC. Time taken ~= 0.05*(num correct)
    #Pass: [known bytes]+[guess byte]+['a'*(total - len(known) - 1)], measure time.
    #Iterate over guesses until time taken increases, then reset and continue.
    validchars = string.hexdigits[:-6]
    padding = 'a'*40
    known_bytes = ''
    for i in range(40):
        time.sleep(1)
        padding = padding[:-1]
        kbi = known_bytes
        for gbi in range(len(validchars)):
            guess_string = known_bytes + validchars[gbi] + padding
            taken = 0.000
            pre_t = time.time()
            res = res = make_request(
                'http://localhost:9030/test?file='+fn+'&signature='+guess_string)
            taken += time.time() - pre_t
            print str(taken*1000)
            if res[1]:
                print 'Success, found HMAC digest: '+ guess_string
                exit(0)
            if taken > st*(i+2):
                print 'char: '+validchars[gbi]+' took: '+str(taken*1000)+' ms.'
                known_bytes += validchars[gbi]
                break
        if kbi == known_bytes:
            raise Exception("failed to find any byte in position: "+str(i))
        
                
                
            
            
            