#! /usr/bin/env python
__author__ = 'Siyi Cai'


if __name__ == '__main__':

    word =["A","B","C","D","E","F","G","H","I","J","K","L","M",
          "N","O","P","Q","R","S","T","U","V","W","X","Y","Z",
           "a","b","c","d","e","f","g","h","i","j","k","l","m",
          "n","o","p","q","r","s","t","u","v","w","x","y","z"]
    #open key.txt and get key as str.
    with open("key.txt") as keyFile:
        key=keyFile.read()
    #open input.txt and get plaintxt as str
    with open("input.txt") as inputFile:
        plain=inputFile.read()
    #convert both key and plaintext into list
    keyList=list(key)
    plainList=list(plain)
    cnt=0
    cipher=""
    #print(word)
    #genenate codebook for each character and get the cipher based on the index of character in the word list.
    for alph in plainList:
        shift = cnt % len(keyList)
        #print("CHECK!!!!!!")
        #print(keyList[shift])
        codeBook=word[word.index(keyList[shift]):]+word[0:word.index(keyList[shift])]
        cipher += codeBook[word.index(alph)]
        cnt+=1
        #print(codeBook)
    print(cipher)
    outputFile=open("output.txt", "w")
    outputFile.write(cipher)

# Sample #1
#key : AbRaCaDaBra
#plaintext: sdnFFaandjddfwe
#cipher: sEEfHAdNeaDdGNE

# Sample #2
# key : AAABBB
# plaintext: AbCDeF
# cipher: AbCEfG

#Sample #3
#key : CCCabc
#plaintext: AAaCCb
#cipher: CCccdD
