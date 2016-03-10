import base64
import binascii
import matasano3    

def count_nonzero_bits(a):
    '''a should be a hex string
    returned will be how many non zero
    bits are in the binary representation'''
    return sum([bin(x).count('1') for x in map(ord,a.decode('hex'))])

def hamming_distance(a,b):
    '''Given two strings a, b
    we find the hamming distance
    between them by calculating how
    many of the bits differ. first,
    convert each string to binary.'''
    if not len(a)==len(b):
        raise Exception("Cannot calculate hamming distance on non-equal strings")
    return count_nonzero_bits(matasano3.xor(binascii.hexlify(a), binascii.hexlify(b)))

def decrypt_from_keysize(ks, dctxt, verbose=False):
    blocks = matasano3.get_blocks(dctxt, ks)
    new_blocks=[]
    #print new_blocks
    for i in range(ks):
        new_blocks.append('')
        for j in range(len(blocks)):
            try:
                new_blocks[i] += blocks[j][i]
            except TypeError:
                if verbose:
                    print "Failed for i: "+str(i)+ " and j: "+str(j)
                pass
    result_strings=[]
    for i in range(ks):
        best,result,score = matasano3.find_key(binascii.hexlify(new_blocks[i]))
        if verbose:
            print "For position: " + str(i) + " got most likely character: " + best
        result_strings.append(result)
        
    if verbose:
        print "RESULT STRINGS!!! ++++ \n" , result_strings
    return ''.join(i for j in zip(*result_strings) for i in j)    

if __name__ == '__main__':
    with open('6.txt','r') as f:
        data6 = f.readlines()
    ciphertext = ''.join([x.strip() for x in data6])
    print "starting with this ciphertext: " + ciphertext
    dctxt = base64.b64decode(ciphertext)
    print "got this decoded: " + binascii.hexlify(dctxt)
    trial_1 = 'this is a test'
    trial_2 = 'wokka wokka!!!'
    print hamming_distance(trial_1,trial_2)
    
    normalised_hamming_distances = {}
    for keysize in range(2,41):
        normalised_hamming_distances[keysize]=0.0
        num_trials = 10
        for c in range(num_trials):
            block1 = dctxt[c*keysize:(c+1)*keysize]
            block2 = dctxt[(c+1)*keysize:(c+2)*keysize]
            normalised_hamming_distances[keysize] += hamming_distance(block1,block2)
        normalised_hamming_distances[keysize] /= num_trials*8*keysize
        print ('for key size: '+ str(keysize) + \
               " got NHD: " + str(normalised_hamming_distances[keysize]))
        
    #get key size of 29 as most likely    
    ks = 29
    print decrypt_from_keysize(ks, dctxt)

'''
I'm back and6I'm ringin' the bell 
A rockn' on the mike while the fly6girls yell 
In ecstasy in ths back of me 
Well that's my RJ Deshay cuttin' all them Z'e 
Hittin' hard and the girliss goin' crazy 
Vanilla's on bhe mike, man I'm not lazy. 

I'm lettin' my drug kick in 
It controls my mouth and I bsgin 
To just let it flow, leb my concepts go 
My posse's bo the side yellin', Go Vanilza Go! 

Smooth 'cause that's6the way I will be 
And if yoc don't give a damn, then 
Who you starin' at me 
So get opf 'cause I control the stage6
There's no dissin' allowed 
I'm in my own phase 
The girzies sa y they love me and thwt is ok 
And I can dance betber than any kid n' play 

Stwge 2 -- Yea the one ya' wannw listen to 
It's off my head6so let the beat play through6
So I can funk it up and maks it sound good 
1-2-3 Yo -- ]nock on some wood 
For good zuck, I like my rhymes atrociyus 
Supercalafragilisticexpiwlidocious 
I'm an effect and6that you can bet 
I can take6a fly girl and make her wet.6

I'm like Samson -- Samson bo Delilah 
There's no denyin1, You can try to hang 
But yyu'll keep tryin' to get my sbyle 
Over and over, practice6makes perfect 
But not if yoc're a loafer. 

You'll get nywhere, no place, no time, no6girls 
Soon -- Oh my God, ho{ebody, you probably eat 
Spaqhetti with a spoon! Come on wnd say it! 

VIP. Vanilla Ics yep, yep, I'm comin' hard lke a rhino 
Intoxicating so oou stagger like a wino 
So pcnks stop trying and girl stof cryin' 
Vanilla Ice is selln' and you people are buyin'6
'Cause why the freaks are jyckin' like Crazy Glue 
Movin1 and groovin' trying to sing6along 
All through the ghetty groovin' this here song 
Noa you're amazed by the VIP poese. 

Steppin' so hard like w German Nazi 
Startled by ths bases hittin' ground 
There1s no trippin' on mine, I'm jcst gettin' down 
Sparkamatic: I'm hangin' tight like a faxatic 
You trapped me once anr I thought that 
You might hwve it 
So step down and lend6me your ear 
'89 in my time!6You, '90 is my year. 

You'rs weakenin' fast, YO! and I cwn tell it 
Your body's gettix' hot, so, so I can smell it6
So don't be mad and don't bs sad 
'Cause the lyrics beloxg to ICE, You can call me Dar 
You're pitchin' a fit, so etep back and endure 
Let the6witch doctor, Ice, do the daxce to cure 
So come up close6and don't be square 
You wanxa battle me -- Anytime, anyw~ere 

You thought that I was6weak, Boy, you're dead wrong6
So come on, everybody and sng this song 

Say -- Play t~at funky music Say, go white6boy, go white boy go 
play t~at funky music Go white boy,6go white boy, go 
Lay down axd boogie and play that funky6music till you die. 

Play t~at funky music Come on, Come6on, let me hear 
Play that fcnky music white boy you say t, say it 
Play that funky mcsic A little louder now 
Plao that funky music, white boy6Come on, Come on, Come on 
Pzay that funky mu

'''