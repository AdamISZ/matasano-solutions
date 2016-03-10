import matasano3
cts=[]
with open('4.txt','r') as f:
    lines = f.readlines()
for l in lines:
    cts.append(l.strip())
    
for l in cts:
    best,result,score = matasano3.find_key(l)
    if score > 27: #a couple off the max in case we missed some punctuation
        print ('got score: ', score)
        print ('Best char was: ', best, ' and result was: ', result)
    
    