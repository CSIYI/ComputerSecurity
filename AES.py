#! /usr/bin/env python
__author__ = 'Siyi Cai'

from BitVector import *
from numpy import *
#global variables
AES_modulus = BitVector(bitstring='100011011')
subBytesTable = []                                                  # for encryption
invSubBytesTable = []
#MixColumns coeficient for encryption
MUL02 = BitVector(intVal=2, size=8)
MUL03 = BitVector(intVal=3, size=8)
#MixColumns coeficient for decryption
MUL0E = BitVector(intVal=14, size=8)
MUL0B = BitVector(intVal=11, size=8)
MUL0D = BitVector(intVal=13, size=8)
MUL09 = BitVector(intVal=9, size=8)

#arrange input arrays
def gen128bits(arr):
    bit= BitVector(intVal=0,size=128)
    for j in range(4):
        for i in range(4):
            bit[(i+j*4)*8:(i+j*4)*8+8]=arr[i][j]
    return(bit)
def genStateArr(input_block):
    StateArr = [[0 for x in range(4)] for x in range(4)]
    for i in range(4):
        for j in range(4):
            StateArr[j][i] = input_block[32 * i + 8 * j:32 * i + 8 * (j + 1)]

    return (StateArr)
#generate S_box
def genTables(en_de):
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    if (en_de=="EN"):
        for i in range(0, 256):
            # For the encryption SBox
            a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            # For bit scrambling for the encryption SBox entries:
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            subBytesTable.append(a)
        return (subBytesTable)
    else:

        for i in range(0, 256):
            # For the decryption Sbox:
            b = BitVector(intVal = i, size=8)
            # For bit scrambling for the decryption SBox entries:
            b1,b2,b3 = [b.deep_copy() for x in range(3)]
            b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d

            check = b.gf_MI(AES_modulus, 8)
            b = check if isinstance(check, BitVector) else BitVector(intVal = 0, size =8)
            invSubBytesTable.append(b)
        #print(invSubBytesTable)
        return(invSubBytesTable)

def MixColums(s_out):
    ColMix = [[0 for x in range(4)] for x in range(4)]
    #1st row [2,3,1,1]
    for i in range(4):
        ColMix[0][i] = s_out[0][i].gf_multiply_modular(MUL02, AES_modulus, 8)\
               ^s_out[1][i].gf_multiply_modular(MUL03, AES_modulus, 8)\
               ^s_out[2][i]^s_out[3][i]

    # 2nd row [1,2,3,1]
    for i in range(4):
        ColMix[1][i] = s_out[0][i] ^ s_out[1][i].gf_multiply_modular(MUL02, AES_modulus, 8) \
                   ^ s_out[2][i].gf_multiply_modular(MUL03, AES_modulus, 8) \
                   ^ s_out[3][i]

    # 3rd row [1,1,2,3]
    for i in range(4):
        ColMix[2][i] = s_out[0][i] ^ s_out[1][i] \
                       ^ s_out[2][i].gf_multiply_modular(MUL02, AES_modulus, 8) \
                           ^ s_out[3][i].gf_multiply_modular(MUL03, AES_modulus, 8)
    # 4th row [3,1,1,2]
    for i in range(4):
        ColMix[3][i] = s_out[0][i].gf_multiply_modular(MUL03, AES_modulus, 8) \
                       ^ s_out[1][i] ^ s_out[2][i] \
                       ^ s_out[3][i].gf_multiply_modular(MUL02, AES_modulus, 8)
    return(ColMix)

def InvMixColums(s_out):
    ColMix = [[0 for x in range(4)] for x in range(4)]
    # 1st row [0E,0B,0D,09]
    for i in range(4):
        ColMix[0][i] = s_out[0][i].gf_multiply_modular(MUL0E, AES_modulus, 8) \
                       ^ s_out[1][i].gf_multiply_modular(MUL0B, AES_modulus, 8) \
                       ^ s_out[2][i].gf_multiply_modular(MUL0D, AES_modulus, 8) ^\
                       s_out[3][i].gf_multiply_modular(MUL09, AES_modulus, 8)

    # 2nd row [09,0E,0B,0D]
    for i in range(4):
        ColMix[1][i] = s_out[0][i].gf_multiply_modular(MUL09, AES_modulus, 8) \
                       ^ s_out[1][i].gf_multiply_modular(MUL0E, AES_modulus, 8) \
                       ^ s_out[2][i].gf_multiply_modular(MUL0B, AES_modulus, 8) \
                       ^ s_out[3][i].gf_multiply_modular(MUL0D, AES_modulus, 8)

    # 3rd row [0D,09,0E,0B]
    for i in range(4):
        ColMix[2][i] = s_out[0][i].gf_multiply_modular(MUL0D, AES_modulus, 8)\
                       ^ s_out[1][i].gf_multiply_modular(MUL09, AES_modulus, 8) \
                       ^ s_out[2][i].gf_multiply_modular(MUL0E, AES_modulus, 8) \
                       ^ s_out[3][i].gf_multiply_modular(MUL0B, AES_modulus, 8)
    # 4th row [0B,0D,09,0E]
    for i in range(4):
        ColMix[3][i] = s_out[0][i].gf_multiply_modular(MUL0B, AES_modulus, 8) \
                       ^ s_out[1][i].gf_multiply_modular(MUL0D, AES_modulus, 8)\
                       ^ s_out[2][i].gf_multiply_modular(MUL09, AES_modulus, 8) \
                       ^ s_out[3][i].gf_multiply_modular(MUL0E, AES_modulus, 8)
    return (ColMix)

def gee(keyword, round_constant, byte_sub_table):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += byte_sub_table[rotated_word[8*i:8*i+8].intValue()]
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant

def gen_key_schedule_128(key_bv):
    byte_sub_table = genTables("EN")
    #  We need 44 keywords in the key schedule for 128 bit AES.  Each keyword is 32-bits
    #  wide. The 128-bit AES uses the first four keywords to xor the input block with.
    #  Subsequently, each of the 10 rounds uses 4 keywords from the key schedule. We will
    #  store all 44 keywords in the following list:
    key_words = [None for i in range(44)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(4):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(4,44):
        if i%4 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-4] ^ kwd
        else:
            key_words[i] = key_words[i-4] ^ key_words[i-1]


    return key_words

def encript(input_block, s_table, round_key, round_num):
    #generate statearray
    statearray = genStateArr(input_block)
    #single byte based substitution
    s_out = [[0 for x in range(4)] for x in range(4)]
    for i in range(4):
        for j in range(4):
            s_out[i][j] = s_table[int(statearray[i][j])]
    #row-wise permutation
    s_out[1] = s_out[1][1:] + s_out[1][0:1]
    s_out[2] = s_out[2][2:4] + s_out[2][0:2]
    s_out[3] = s_out[3][-1:] + s_out[3][:-1]

    #column-wise mixing
    if (round_num!=10):
        ColMix=MixColums(s_out)
        # addition of the round key
        bit_128 = gen128bits(ColMix)
    else:
        bit_128 = gen128bits(s_out)
    cipher=bit_128^round_key
    return (cipher)

#inverse subtitude bytes
#add round key
#inverse mix columns
def decript(input_block, s_table, round_key, round_num):
    # generate statearray
    statearray = genStateArr(input_block)
    # inverse shift rows
    s_out = [[0 for x in range(4)] for x in range(4)]
    s_out[0] = statearray[0]
    s_out[1] = statearray[1][-1:] + statearray[1][:-1]
    s_out[2] = statearray[2][2:4] + statearray[2][0:2]
    s_out[3] = statearray[3][1:] + statearray[3][0:1]

    # inverse subtitude bytes
    sub_out=[[0 for x in range(4)] for x in range(4)]
    for i in range(4):
        for j in range(4):
            sub_out[i][j] = s_table[int(s_out[i][j])]
    # add round key

    bit_128 = gen128bits(sub_out)
    cipher = bit_128 ^ round_key
    # inverse mix columns
    if (round_num!=10):
        ColMix=InvMixColums(genStateArr(cipher))
        return(gen128bits(ColMix))
    else:
        return(cipher)

#get plaintext input
#bv = BitVector(filename='plaintext.txt')
#get rounds key for "yayboilermakers!"
key_bv = BitVector(textstring="yayboilermakers!")
key_words=gen_key_schedule_128(key_bv)
round_keys = [None for i in range(11)]
for i in range(11):
        round_keys[i] = (key_words[i * 4] + key_words[i * 4 + 1] + key_words[i * 4 + 2] +key_words[i * 4 + 3])

#encryption
outputFile=open("encrypted.txt","wb")
bv = BitVector(filename='plaintext.txt')
while (bv.more_to_read):
    bitvec=bv.read_bits_from_file(128)
    if (len(bitvec) > 0):
        s_table=genTables("EN")
        #first round and the key
        bitvec ^= round_keys[0]
        for i in range(1,11):
            bitvec=encript(bitvec, s_table, round_keys[i], i)
        print(bitvec.get_bitvector_in_hex())
        bitvec.write_to_file(outputFile)
outputFile.close()


#decryption
#get cipher input

bv = BitVector(filename='encrypted.txt')
outputFile=open("decrypted.txt","wb")
while (bv.more_to_read):
    bitvec = bv.read_bits_from_file(128)
    if (len(bitvec) > 0):
        bitvec ^= round_keys[10]
        inv_s_table=genTables("DE")
        for i in range(9, -1, -1):
            bitvec = decript(bitvec, inv_s_table, round_keys[i], 10-i)
        bitvec.write_to_file(outputFile)
outputFile.close()
