#! /usr/bin/env python
__author__ = 'Siyi Cai'


from BitVector import *
from PrimeGenerator import *
import numpy as np
import sys

#Root function from lecture
def solve_pRoot(p,y):
    p = long(p);
    y = long(y);
    # Initial guess for xk
    try:
        xk = long(pow(y,1.0/p));
    except:
        # Necessary for larger value of y
        # Approximate y as 2^a * y0
        y0 = y;
        a = 0;
        while (y0 > sys.float_info.max):
            y0 = y0 >> 1;
            a += 1;
        # log xk = log2 y / p
        # log xk = (a + log2 y0) / p
        xk = long(pow(2.0, ( a + np.log2(float(y0)) )/ p ));

    # Solve for x using Newton's Method
    err_k = pow(xk,p)-y;
    while (abs(err_k) > 1):
        gk = p*pow(xk,p-1);
        err_k = pow(xk,p)-y;
        xk = -err_k/gk + xk;
    return xk

#GCD function from lecture
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

#Key generator for RSA
def KeyGeneratorRSA():
    e=3
    #Build PrimeGenerator with 128 bits 
    pp=PrimeGenerator(bits =128)

    while True:
    	#Generate p,q and check them
        p=BitVector(intVal=pp.findPrime())
        q=BitVector(intVal=pp.findPrime())
        if p != q and p[0]&p[1]&q[0]&q[1] and bgcd(int(p)- 1,e) ==1 and bgcd(int(q)-1,e)==1:
            break
    #Get n
    n=int(p)*int(q)
    #public key
    pubKey = [e,n]

    return pubKey,n

#Encryption function
def encryption(pubKey, inputFile):
    #Get content
    content = BitVector(filename=inputFile)
    #List for encrypted cipher in HEX
    CHex=[]
    #RSA
    while (content.more_to_read):
        bitvec = content.read_bits_from_file(128)
        while (bitvec.length() < 128):
            bitvec = bitvec + BitVector(textstring="\n")
        bitvec.pad_from_left(128)
        M=int(bitvec)
        cipher = pow(M,pubKey[0],pubKey[1])
        cipher_bv=BitVector(intVal=cipher, size= 256)
        CHex.append(cipher_bv.get_bitvector_in_hex())

    return CHex

#crackRSA using CTR
def crackRSA(m1,m2,m3, C1, C2, C3, outputFile):
    outputFile = open(outputFile, "wb")
    
    M = m1 * m2 * m3
    #Get Ms
    M1 = M / m1
    M2 = M / m2
    M3 = M / m3

    m1_modulus = BitVector(intVal=m1)
    m2_modulus = BitVector(intVal=m2)
    m3_modulus = BitVector(intVal=m3)

    M1_bv = BitVector(intVal=M1)
    M2_bv = BitVector(intVal=M2)
    M3_bv = BitVector(intVal=M3)

    #Get Ms' multiplicative inverse
    M1_MI = M1_bv.multiplicative_inverse(m1_modulus)
    M2_MI = M2_bv.multiplicative_inverse(m2_modulus)
    M3_MI = M3_bv.multiplicative_inverse(m3_modulus)


    for i in range(len(C1)):

        a1_bv = BitVector(hexstring=C1[i])
        a1 = int(a1_bv)
        a2_bv = BitVector(hexstring=C2[i])
        a2 = int(a2_bv)
        a3_bv = BitVector(hexstring=C3[i])
        a3 = int(a3_bv)
	#Get plaintext
        M_cube = (a1 * M1 * int(M1_MI) + a2 * M2 * int(M2_MI) + a3 * M3 * int(M3_MI)) % M
        MM = solve_pRoot(3, M_cube)
        M_bv = BitVector(intVal=MM, size=128)
        M_bv.write_to_file(outputFile)
    outputFile.close()

if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("Call syntax:  Cai_breakRSA_hw06.py  message.txt cracked.txt")

    #Op = sys.argv[1]
    #inputfile = sys.argv[2]
    #outputfile = sys.argv[3]

    pubKey1, n1 = KeyGeneratorRSA()
    C1=encryption(pubKey1, "message.txt")
    pubKey2, n2 = KeyGeneratorRSA()
    C2=encryption(pubKey2, "message.txt")
    pubKey3, n3 = KeyGeneratorRSA()
    C3=encryption(pubKey3, "message.txt")
    file1=open ("EncryptionInHex1.txt","w")
    file1.write("n:"+ str(n1)+"\n")
    for ele in C1:
    	file1.write(ele)
    file2= open ("EncryptionInHex2.txt","w")
    file2.write("n:"+ str(n2)+"\n")
    for ele in C2:
    	file2.write(ele)
    file3= open ("EncryptionInHex3.txt","w")
    file3.write("n:"+ str(n3)+"\n")
    for ele in C3:
    	file2.write(ele)
    		

    crackRSA(n1, n2, n3, C1, C2, C3, "cracked.txt")




