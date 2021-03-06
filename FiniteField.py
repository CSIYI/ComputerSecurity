#! /usr/bin/env python
__author__ = 'Siyi Cai'

import sys
#get user input from prompt
user_input=input("Please enter a number smaller than 50: ")
#open up output file for writing
file=open("output.txt","w")
#check user_input is bigger than 50 or negative
while (user_input>=50 or user_input<1):
    print("User input should be bigger than 50.")
    user_input = input("Please enter a number smaller than 50: ")
# 1 is a special case
if user_input ==1:
    file.write("ring")
    sys.exit()
GCD=[]
#check the Z set to get the GCD
for i in range(1,user_input):
    a=user_input
    b = i
    while b:
        a, b = b, a % b
    #if the result GCD not equal to 1, which mean that number desn't have MI, so it is a ring
    if a != 1:
        file.write("ring")
        print("ring")
        sys.exit()
#if all set has 1 as GCD, the Z set of user_input is a field.
file.write("field")
print("field")
#sample1
#user_input: 49
#output: ring

#sample2
#user_input: 47
#output: field

#sample3
#user_input: 12
#output: ring

#sample4
#user_input: 17
#output: field

#sample5
#user_input: 1
#output: ring

