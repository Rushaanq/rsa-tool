#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Dec 10 13:59:12 2021

@author: Rushaan Kamran Qureshi - 40190342
"""

''' Import required libraries '''

import binascii
import sympy as sp
import random as rd

''' Define Mathematical functions '''

''' GCD -> returns gcd (x,y) '''

def gcd(x, y):
    while (y!=0):
        x, y = y, x%y
    return x

''' Euclidean GCD -> returns gcd (x,y), a and b. a x * by = gcd(a,b) '''
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b%a,a)
    return (g, x - (b//a) * y, y)

''' Mod Inverse -> returns x = a^-1 mod m '''
def mod_inv(num, mod):
    gcd, x, y = egcd(num, mod)
    if gcd != 1:
        raise Exception('Mod inverse not possible')
    return x%mod

''' Square Multiply Modular Exponentiation using recursive function calls. 

If the exponent is even we break the problem in half and solve the problem and return sol^2  mod N

if the exponent is odd we break 1 exponent as a mod n is solvable and the function is called on the rest.
for example:-

17^4 mod 77 is broken into 17^2 mod 77 and 17^2 mod 77, which is again, broken into
17 mod 77 and returned above. '''

def sq_mul(a,m,n):
    if m==0:    return 1 #check if exponent is 0, answer is 1
    elif (m%2==0): 
        sol= sq_mul(a,m//2,n)
        return (sol*sol)%n
    else:
        return (((a%n)*sq_mul(a,m-1,n))%n)


'''  keygen -> Generates Public and Private key pairs.  ''' 

def keygen():

    
    ''' Initialize required variables '''
    primes=[]
    list_e=[]
    
    ''' Initialize min and max 16 bit int values '''
    min=int('1000000000000000',2)
    max=int('1111111111111111',2)
    
    ''' Generate list of primes in the 16 bit number range '''
    for i in range(min,max):
        
        if sp.isprime(i):
            primes.append(i)
    ''' Choose P and Q randomly from 16 bit numbers '''       
    p=rd.choice(primes)
    '''To prevent P==Q  '''
    primes.remove(p)        
    q=rd.choice(primes)

    ''' Calc N = P * Q and Phi_N = ( P - 1 ) * ( Q - 1 ) '''
    N=p*q
    phi=(p-1)*(q-1)
    
    ''' Generate list of e such that gcd(potential_e,phi)==1 and e < Phi(N) in a limited range'''
    for j in range(10000,100000):
        if gcd(j,phi)==1:
            list_e.append(j)
    e=rd.choice(list_e)
    
    ''' Get private key; d = e^-1 mod Phi_N '''
    d=mod_inv(e,phi)
    
    print("\n--------------------------Generated Keys-----------------------\nKey generation successful!\nYour generated parameters are:\nP = "+str(p)+"\nQ = "+str(q)+"\nN = "+str(N)+"\nPhi_N = "+str(phi)+"\nPublic key e = "+str(e)+"\nPrivate key d = "+str(d)+'\n---------------------------------------------------------------')

''' encryption() -> Encrypt message using partner's Public Key ( N , e )  '''

def encryption():
    tmsg=input('Please enter your message to encrypt:\n')
    pkey=int(input('Enter your partner'+"'"+'s'+' public key (e):\n'))
    pn=int(input('Enter your partner'+"'"+'s'+' N:\n'))
    
    ''' Divide message into 3 byte chunks  '''
    blk = [tmsg[i:i+3] for i in range(0, len(tmsg), 3)]
    print("Message chunks: ",blk)
    enc=[]
    
    ''' Convert each chunk into hexadecimal string after you encode it into utf-8 character set. 
        Then, convert the hexadecimal string into the respective integer representation 
        and append the element to list enc '''
    for i in blk:
        iint='0x'+i.encode("utf-8").hex()
        po=int(iint,16)
        enc.append(po)
    #   print("Integer message chunks to encrypt:",enc)
    cipher=[]
    
    ''' Encrypt each integer chunk by C = M^e mod N using square multiply function and output the cipher text'''
    
    for i in enc:
        cipher.append(sq_mul(i,pkey,pn))
    print ("Cipher text:",cipher)


'''  decryption() -> Decrypt message using your Private Key ( N , d )  ''' 
def decryption():
    ctext=input('Enter the ciphertext: ').split()
    n=int(input("Enter your N: "))
    d=int(input("Enter your private key (d): "))
    m=[]
    dec_txt=''
    
    ''' Decrypt each encrypted chunk using M = C^d mod N. 
        Then, convert the plaintext integer chunks into the respective hexadecimal representation
        then convert it to byptes and decode it to utf-8 characterset encoding.
        
        We then concatenate the decrypted message chunks to obtain the decrypted message '''
    
    for i in ctext:
        hx=hex(sq_mul(int(i),d,n))[2:]

        strhx=bytes.fromhex(hx).decode('utf-8')
        m.append(strhx)
        dec_txt=dec_txt+strhx
    print("Message chunks:",m)
    print('The decrypted text is: '+ dec_txt)

'''  sign_msg() -> Sign you message using your Private Key ( N , d )  ''' 
def sign_msg():
    n=int(input("Enter your N: "))
    d=int(input("Enter your private key: "))
    msgtosig=input("Enter message to sign: ")
    blk = [msgtosig[i:i+3] for i in range(0, len(msgtosig), 3)]
    print("Message Chunks:",blk)
    tosign=[]
    for i in blk:
        iint='0x'+i.encode("utf-8").hex()
        po=int(iint,16)
        tosign.append(po)
#   print(tosign) integer rep of message to be signed
    sign=[]
    '''Sign each message chunk using S=m^d mod N'''
    #Verification : S^e mod N
    for m in tosign:
        sign.append(sq_mul(m,d,n))
    print('Signed Message: '+msgtosig)
    print('Signature: ')
    print(sign)
    
'''  verify() -> Verify message using your Public Key ( N , e )  ''' 
def verify():
    ctmsg=input("Enter the signed message in plaintext: ")
    msgtover=input("Enter the signature: ").split()
    vere=int(input('Enter signer'+"'"+'s e: '))
    vern=int(input('Enter signer'+"'"+'s N: '))
    intmsg=[]
    
    '''Verify each message chunk using m = S^e mod N'''
    for i in msgtover:
        intmsg.append(sq_mul(int(i),vere,vern))
    #print(intmsg)
    ''' inttohex and hex to str '''
    sigtxm=[]
    signedstr=''
    for i in intmsg:
        hx=hex(i)[2:]
        try:
            strhx=bytes.fromhex(hx).decode('utf-8')
            sigtxm.append(strhx)
            signedstr=signedstr+strhx
        except:
            print("Invalid input or Signature not valid. \nAborting program * * * \nPlease check input and try again.")
    #print(sigtxm)
    #print(signedstr)
    if signedstr==ctmsg:
        print("\nSignature verified! The given signature corresponds to the signed text. \nSigned text: "+signedstr)
    else:
        print("Signature NOT verified!\n"+signedstr+' is not the a signed message for the entered public key: '+str(vere),str(vern))
    
print("======================================================================\n                     Welcome to Rushaan's RSA tool!\n======================================================================\n")
print("\nSelect your operation of choice:")
choice=input('>>>>>1) Generate Keys \n>>>>>2) Encryption\n>>>>>3) Decryption\n>>>>>4) Sign a message\n>>>>>5) Verify a message \nEnter your choice: ')


if choice=='1':
    keygen()
if choice=='2':
    encryption()
if choice=='3':
    decryption()
if choice=='4':
    sign_msg()
if choice=='5':
    verify()
