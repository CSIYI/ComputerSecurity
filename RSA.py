#! /usr/bin/env python
__author__ = 'Siyi Cai'

from BitVector import *
from PrimeGenerator import *

def bgcd(a,b):
    if a == b: return a                                         #(A)
    if a == 0: return b                                         #(B)
    if b == 0: return a                                         #(C)
    if (~a & 1):                                                #(D)
        if (b &1):                                              #(E)
            return bgcd(a >> 1, b)                              #(F)
        else:                                                   #(G)
            return bgcd(a >> 1, b >> 1) << 1                    #(H)
    if (~b & 1):                                                #(I)
        return bgcd(a, b >> 1)                                  #(J)
    if (a > b):                                                 #(K)
        return bgcd( (a-b) >> 1, b)                             #(L)
    return bgcd( (b-a) >> 1, a )                                #(M)

def KeyGeneratorRSA():
    e=65537
    pp=PrimeGenerator(bits =128)

    while True:
        p=BitVector(intVal=pp.findPrime())
        q=BitVector(intVal=pp.findPrime())
        if p != q and p[0]&p[1]&q[0]&q[1] and bgcd(int(p)- 1,e) ==1 and bgcd(int(q)-1,e)==1:
            break
    n=int(p)*int(q)
    n_totient=(int(p)-1)*(int(q)-1)
    totient_modulus = BitVector(intVal=n_totient)
    e_bv = BitVector(intVal=e)
    d = e_bv.multiplicative_inverse(totient_modulus)

    pubKey = [e,n]
    priKey = [int(d),n]

    return pubKey,priKey,p,q

def encryption(pubKey, inputFile, outputFile):
    content = BitVector(filename=inputFile)
    outputFile = open(outputFile, "wb")
    CHex=[]
    while (content.more_to_read):
        bitvec = content.read_bits_from_file(128)
        while (bitvec.length() < 128):
            bitvec = bitvec + BitVector(textstring="\n")
        bitvec.pad_from_left(128)
        M=int(bitvec)
        cipher = pow(M,pubKey[0],pubKey[1])
        cipher_bv=BitVector(intVal=cipher, size= 256)
        CHex.append(cipher_bv.get_bitvector_in_hex())
        cipher_bv.write_to_file(outputFile)

    outputFile.close()
    with open("EncryptionInHex.txt","w") as File:
        for ele in CHex:
            File.write(ele)
    File.close()

def decryption(priKey,  p, q,inputfile, outputfile):
    outputFile = open(outputfile, 'wb')
    MHex=[]
    bv = BitVector(filename=inputfile)
    d = priKey[0]
    n = priKey[1]
    p_MI = p.multiplicative_inverse(q)
    q_MI = q.multiplicative_inverse(p)
    Xp = int(q) * int(q_MI)
    Xq = int(p) * int(p_MI)
    while bv.more_to_read:
        bitvector = bv.read_bits_from_file(256)
        C = int(bitvector)
        Vp = pow(C, d, int(p))
        Vq = pow(C, d, int(q))

        M = (Vp * Xp + Vq * Xq) % n
        M_bv = BitVector(intVal=M, size=256)
        [zero,mm]=M_bv.divide_into_two()
        MHex.append(mm.get_bitvector_in_hex())
        mm.write_to_file(outputFile)
    outputFile.close()
    with open("DecryptionInHex.txt","w") as File:
        for ele in MHex:
            File.write(ele)
    File.close()


if __name__ == "__main__":
    #if len(sys.argv) != 4:
    #    sys.exit("Call syntax:  Cai_RSA_hw06.py  op inputfile outputfile")

    #Op = sys.argv[1]
    #inputfile = sys.argv[2]
    #outputfile = sys.argv[3]

    pubKey, priKey, p, q=KeyGeneratorRSA()
    print("p: "+str(int(p)))
    print("q: "+str(int(q)))
    print("d: "+str(priKey[0]))
    '''
    if sys.argv[1] == "-e":
        encryption(priKey, inputfile, outputfile)
    elif sys.argv[1] == "-d":
        decryption(pubKey,int(p),int(q),inputfile, outputfile)
    else:
        exit()
    '''
    encryption(pubKey, "message.txt", "output.txt")
    decryption(priKey, p, q, "output.txt", "decrypted.txt")








