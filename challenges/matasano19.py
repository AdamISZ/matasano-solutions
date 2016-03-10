#matasano 3.19

import slowaes
import base64
import binascii
import matasano3
import matasano12
import matasano18
import os    
txt64 = [
    'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
    'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
    'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
    'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
    'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
    'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
    'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
    'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
    'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
    'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
    'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
    'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
    'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
    'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
    'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
    'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
    'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
    'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
    'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
    'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
    'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
    'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
    'U2hlIHJvZGUgdG8gaGFycmllcnM/',
    'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
    'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
    'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
    'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
    'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
    'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
    'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
    'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
    'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
    'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
    'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
    'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
    'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
    'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
    'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
    'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
    'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4='
]
if __name__ == '__main__':
    bs = 16
    k = matasano12.fixed_k
    txt = [base64.b64decode(_) for _ in txt64]

    #encrypt in aes-ctr mode with the new random key, but using a zero nonce
    #note that it's a separate encryption for *each* text
    ciphertexts = [matasano18.aes_ctr_crypt(_, k, 0) for _ in txt]
    print 'got these ciphertexts: '
    print [binascii.hexlify(_) for _ in ciphertexts]
    
    #simple approach; perhaps not was intended for this challenge?
    #loop over all possible keystream 1st bytes, xor them with
    #ciphertext first bytes and see which candidate gives rise to
    #the most likely set of plaintext first bytes. Etc for other bytes.
    N = 1
    league_table = {}
    best_cols = {}
    for i in range(max([len(_) for _ in ciphertexts])):
        league_table[i]={}
        best_cols[i]=[]
        ctxt_bytes = []
        for c in ciphertexts:
            if len(c)>i:
                ctxt_bytes.append(c[i])
            else:
                ctxt_bytes.append(None)

        for j in range(256):
            ptxt_guesses = []
            for b in ctxt_bytes:
                if not b:
                    ptxt_guesses.append(None)
                else:
                    ptxt_guesses.append(binascii.unhexlify(matasano3.xor(
                        [ord(b)], [j], fmt='ord')))
            #print ptxt_guesses
            #count how many of our plaintext bytes, for this guess, are ascii
            league_table[i][j] = sum([ptxt_guesses.count(_) for _ in matasano3.x])
            
        #finished processing for byte i; print the output for the top N winners
        
        for k in range(N):
            winner = max(league_table[i], key=league_table[i].get)
            best_col = []
            for c in ctxt_bytes:
                if not c:
                    best_col.append(None)
                else:
                    best_col.append(binascii.unhexlify(
                        matasano3.xor([ord(c)], [winner], fmt='ord')))
                    
            best_cols[i].append(best_col)
            del league_table[i][winner]
    
    #aggregate the columns into best guess lines:
    for i in range(len(ciphertexts)):
        guess_lines = []
        for j in range(N):
            guess_lines.append(''.join(filter(None,[best_cols[_][j][i] for _ in best_cols.keys()])))
        #print "**LINE NUMBER: "+str(i)
        print ','.join(guess_lines)
    
    #Note: this gives a big chunk of correct text.
    #There's a lot more you can do in manual iterations:
    #For example, 'i have met then at ckosd of Uad' -> 'ckosd' is probably 'close',
    #so find the keystream byte at index 20 that results in plaintext 'l', fix it,
    #rerun, and so on; with so many ciphertexts it'd be easy to get it almost perfect.
    #Stopping at this point, according to instructions.
    #It's interesting to notice that the wrong bytes are **OFTEN OFF BY 1!**
    #Output: (note the third to last line has a bunch of chars at the end that *would*
    #be difficult to find)
    '''
i have met them at ckosd oa Uad
coming with vivid fades
from counter or desk'amnng'gCed
eighteenth-century hhusds.
i have passed with a'noe oa Ehxc9Cv8
or polite meaninglest wnrdt,
or have lingered awhnle!anc Bat'
polite meaningless whrdr,
and thought before I'hae dhnT
of a mocking tale or'a fibb
to please a companioi
around the fire at toe blue,
being certain that toey!anc x
but lived where motlby hs poCn'
all changed, changed'utuerky

a terrible beauty is'bosn.
that woman's days weue rpeit
in ignorant good wilk,
her nights in argumeit
until her voice grew'shsilk.
what voice more swees tian'hTrn
when young and beautnfum,
she rode to harriers8
this man had kept a tchnol
and rode our winged oorre.
this other his helpeu aod arXes'
was coming into his aorbe;
he might have won faje hn shT x-5

so sensitive his natrre!sebmTd1
so daring and sweet ois!thhuVhim
this other man I had'drdambd
a drunken, vain-glornour lhuE.
he had done most bitser!wrhnV
to some who are near'my!hefrE,
yet I number him in she!soig

he, too, has resignec hhs waCt
in the casual comedy<
he, too, has been chfngdd nnht0qRb.Q
transformed utterly:
a terrible beauty is'bosn.
'''
        
