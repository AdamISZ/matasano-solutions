#matasano 5.36
 
import random
import binascii
import os
from matasano10 import aes_cbc_decrypt, aes_cbc_encrypt
from matasano28 import sha1
from matasano18 import bi2ba
from matasano34 import netsim
from hashlib import sha256
import hmac

#Pre-agreed constants defined as global
g = 2
pstr = """
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff
"""
p = long(eval('0x'+''.join(pstr.split())))
k=3

def sfs2int(*args):
    '''String from sha256 hexdigest of ints.
    Pass a set of ints as args.'''
    sha_input = ''
    for a in args:
        if isinstance(a, str):
            sha_input += a
        else:
            sha_input += bi2ba(a)
    
    x = sha256(sha_input).hexdigest()
    return long(eval('0x'+x))

class Server(object):
    def reset(self):
        self.A = None
        self.B = None
        self.u = None
        self.b = None
        #cheat-y cheat: just set the email
        #and the password here; in reality,
        #there would be no need, you can store
        #self.v and self.salt instead (that is
        #to say, make a database of pairs,
        #thus making rainbow table style attacks
        #difficult.)
        self.email = "me@there.com"
        password = "password"        
        self.salt = random.randint(1, p-1)
        x = sfs2int(self.salt, password)
        self.v = pow(g, x, p)
    
    def recv_email(self, em, A):
        if not em==self.email:
            return None, None
        self.A = A
        self.b = random.randint(1,p-1)
        self.B = (k * self.v +pow(g, self.b, p))%p
        self.u = sfs2int(self.A, self.B)        
        return self.salt, self.B
    
    def recv_token(self, token):
        self.S = pow( (self.A*pow(self.v, self.u, p)) , self.b, p)
        K = sha256(bi2ba(self.S)).digest()
        t = hmac.new(K, bi2ba(self.salt), sha256).hexdigest()
        if t==token:
            return True, 'Access granted.'
        return False, 'Access denied.'
        
if __name__ == '__main__':
    '''TIL what REPL means!
    Implementation of the SRP protocol. Not too hard, reminiscent
    of BIP32 in the use of a tweak.
    Note we set the email, password pair on re-initing the server, which is just 
    a trivial simplification for testing, but I it seems that the idea
    of the protocol is that the server can just store the salt and
    the value v = g^x%p, where x is sha256(salt|pass), which is a very
    strong defence against rainbow table type attacks.
    '''
    
    server = Server()
    badcount = 0
    while True:
        server.reset()
        em = raw_input('Enter your email: ')
        pwd = raw_input('Enter your password: ')
        #gen ephemeral pubkey for this session:
        cheat_values = ['cheat, set A=0', 'cheat, set A=p', 'cheat, set A=2p']
        a = random.randint(1, p-1)
        if pwd == cheat_values[0]:
            A = 0
        elif pwd == cheat_values[1]:
            A = p
        elif pwd == cheat_values[2]:
            A = 2*p
        else:
            A = pow(g, a, p)
        res = server.recv_email(em, A)
        if not res[0] or not res[1]:
            print 'Error, wrong email'
            badcount += 1
            if badcount > 3:
                print 'Go away'
                exit(0)
            continue
        salt = res[0]
        B = res[1]
        u = sfs2int(A, B)
        #compute same x that server computed
        #to test failure case set the salt to zero or something
        x = sfs2int(salt, pwd)
        if pwd in cheat_values:
            S = 0
        else:
            S = pow( (B - k*pow(g, x, p)) , (a + u*x), p)
        K = sha256(bi2ba(S)).digest()
        token = hmac.new(K, bi2ba(salt), sha256).hexdigest()
        print 'calculated your ephemeral token: '+token
        print 'now requesting access'
        res = server.recv_token(token)
        if not res[0]:
            badcount += 1
            if badcount > 3:
                print 'Go away'
                exit(0)
            print res[1]
        else:
            print res[1]
            exit(0)
        
        