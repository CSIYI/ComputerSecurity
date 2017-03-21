#! /usr/bin/env python
__author__ = 'Siyi Cai'

class RC4:
    def __init__(self, keyString):
        self.keyString=keyString

	#function to strip image file, get rid of header
    def StripImgFile(self, imgFile):
    	#read content
        self.lines = open(imgFile).readlines()
        content=""
        #get content after the header
        for ele in self.lines[3:]:
            content+=ele
        return(content)
	#function to generate KSA
    def KSA(self):
        S=range(256)
        K=[ord(x) for x in self.keyString]
        T=[K[x%len(K)]for x in range(256)]
        j=0
        for i in range(256):
            j=(j+S[i]+T[i])%256
            S[i],S[j]=S[j],S[i]
        return(S)
	#encrypt function
    def encrypt(self, orgImg):
    	#open image file to write
        outputFile = open("encrypted.ppm", 'wb')
        #write header
        outputFile.writelines(self.lines[0:3])
		#get KSA
        S=self.KSA()
        i=0
        j=0

        cnt=0
        cipher=[]
		#RC4
        while cnt < len(orgImg):
            i=(i+1)%256
            j=(j+S[i])%256
            S[i], S[j] = S[j], S[i]
            k=(S[i]+S[j])%256
            cipher.append(S[k]^ord(orgImg[cnt]))
            cnt+=1

        outputFile.write(bytearray(cipher))
        outputFile.close()
        return(cipher)
	#decrypt function
    def decrypt(self, cipherImg):
    	#open image file to write
        outputFile = open("decrypted.ppm", 'wb')
        #write header
        outputFile.writelines(self.lines[0:3])
		#get KSA
        S = self.KSA()
        i = 0
        j = 0

        cnt = 0
        decrypt = ""
        dd=[]
        #RC4
        while cnt < len(cipherImg):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = (S[i] + S[j]) % 256
            decrypt+=chr(S[k] ^ cipherImg[cnt])
            dd.append(S[k] ^ cipherImg[cnt])
            cnt += 1
        outputFile.write(bytearray(dd))
        outputFile.close()
        return (decrypt)




if __name__ == "__main__":
    rc4Cipher = RC4("yayboilermakers!")
    originalImage=rc4Cipher.StripImgFile("winterTown.ppm")

    encryptedImage=rc4Cipher.encrypt(originalImage)
    decryptedImage = rc4Cipher.decrypt(encryptedImage)

    if originalImage==decryptedImage:
        print("RC4 is awesome")
    else:
        print("Hmm, something seems fishy!")
