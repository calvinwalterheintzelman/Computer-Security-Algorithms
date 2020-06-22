# ECE 404 Homework 6
# Calvin Walter Heintzelman
# cheintze
# 2/26/2019
# Using python version 3.7.2
# breakRSA.py

import os
import sys
import random
import numpy as np
from BitVector import *

################# Given Code ################

# Author: Tanmay Prakash
#         tprakash at purdue dot edu
# Solve x^p = y for x
# for integer values of x, y, p
# Provides greater precision than x = pow(y,1.0/p)
# Example:
# >>> x = solve_pRoot(3,64)
# >>> x
# 4L

def solve_pRoot(p,y):
    p = int(p);
    y = int(y);
    # Initial guess for xk
    try:
        xk = int(pow(y,1.0/p));
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
        xk = int(pow(2.0, ( a + np.log2(float(y0)) )/ p ));

    # Solve for x using Newton's Method
    err_k = int(pow(xk,p))-y;
    while (abs(err_k) > 1):
        gk = p*int(pow(xk,p-1));
        err_k = int(pow(xk,p))-y;
        xk = int(-err_k/gk) + xk;
    return xk

#############################################

################# Kak's Code ################

class PrimeGenerator( object ):                                              #(A1)

    def __init__( self, **kwargs ):                                          #(A2)
        bits = debug = None                                                  #(A3)
        if 'bits' in kwargs  :     bits = kwargs.pop('bits')                 #(A4)
        if 'debug' in kwargs :     debug = kwargs.pop('debug')               #(A5)
        self.bits            =     bits                                      #(A6)
        self.debug           =     debug                                     #(A7)
        self._largest        =     (1 << bits) - 1                           #(A8)

    def set_initial_candidate(self):                                         #(B1)
        candidate = random.getrandbits( self.bits )                          #(B2)
        if candidate & 1 == 0: candidate += 1                                #(B3)
        candidate |= (1 << self.bits-1)                                      #(B4)
        candidate |= (2 << self.bits-3)                                      #(B5)
        self.candidate = candidate                                           #(B6)

    def set_probes(self):                                                    #(C1)
        self.probes = [2,3,5,7,11,13,17]                                     #(C2)

    # This is the same primality testing function as shown earlier
    # in Section 11.5.6 of Lecture 11:
    def test_candidate_for_prime(self):                                      #(D1)
        'returns the probability if candidate is prime with high probability'
        p = self.candidate                                                   #(D2)
        if p == 1: return 0                                                  #(D3)
        if p in self.probes:                                                 #(D4)
            self.probability_of_prime = 1                                    #(D5)
            return 1                                                         #(D6)
        if any([p % a == 0 for a in self.probes]): return 0                  #(D7)
        k, q = 0, self.candidate-1                                           #(D8)
        while not q&1:                                                       #(D9)
            q >>= 1                                                          #(D10)
            k += 1                                                           #(D11)
        if self.debug: print("q = %d  k = %d" % (q,k))                       #(D12)
        for a in self.probes:                                                #(D13)
            a_raised_to_q = pow(a, q, p)                                     #(D14)
            if a_raised_to_q == 1 or a_raised_to_q == p-1: continue          #(D15)
            a_raised_to_jq = a_raised_to_q                                   #(D16)
            primeflag = 0                                                    #(D17)
            for j in range(k-1):                                             #(D18)
                a_raised_to_jq = pow(a_raised_to_jq, 2, p)                   #(D19)
                if a_raised_to_jq == p-1:                                    #(D20)
                    primeflag = 1                                            #(D21)
                    break                                                    #(D22)
            if not primeflag: return 0                                       #(D23)
        self.probability_of_prime = 1 - 1.0/(4 ** len(self.probes))          #(D24)
        return self.probability_of_prime                                     #(D25)

    def findPrime(self):                                                     #(E1)
        self.set_initial_candidate()                                         #(E2)
        if self.debug:  print("    candidate is: %d" % self.candidate)       #(E3)
        self.set_probes()                                                    #(E4)
        if self.debug:  print("    The probes are: %s" % str(self.probes))   #(E5)
        max_reached = 0                                                      #(E6)
        while 1:                                                             #(E7)
            if self.test_candidate_for_prime():                              #(E8)
                if self.debug:                                               #(E9)
                    print("Prime number: %d with probability %f\n" %
                          (self.candidate, self.probability_of_prime) )      #(E10)
                break                                                        #(E11)
            else:                                                            #(E12)
                if max_reached:                                              #(E13)
                    self.candidate -= 2                                      #(E14)
                elif self.candidate >= self._largest - 2:                    #(E15)
                    max_reached = 1                                          #(E16)
                    self.candidate -= 2                                      #(E17)
                else:                                                        #(E18)
                    self.candidate += 2                                      #(E19)
                if self.debug:                                               #(E20)
                    print("    candidate is: %d" % self.candidate)           #(E21)
        return self.candidate                                                #(E22)

#############################################

################# My Code ###################

def gcd(a, b):  # finds the GCD of a and b
    if a % b == 0:
        return b
    else:
        return gcd(b, a % b)


def exp_mod(text, exp, mod):  # finds text^exp % mod efficiently
    if exp == 0:
        return 1
    else:
        result = 1
        while exp > 0:
            if exp & 1:
                result = (result*text) % mod
            exp = exp >> 1
            text = (text*text) % mod
        return result


def find_message(encrypted_text_list, n_list, e): # finds the message using encrypted file, 3 n's, and e
    total_blocks = len(encrypted_text_list[0])//64
    total_M = BitVector(bitstring='')

    # Calculate constant values
    N = n_list[0] * n_list[1] * n_list[2]
    N0 = N//n_list[0]
    N1 = N//n_list[1]
    N2 = N//n_list[2]
    N0i = int(BitVector(intVal=N0).multiplicative_inverse(BitVector(intVal=n_list[0])))
    N1i = int(BitVector(intVal=N1).multiplicative_inverse(BitVector(intVal=n_list[1])))
    N2i = int(BitVector(intVal=N2).multiplicative_inverse(BitVector(intVal=n_list[2])))

    # crack the message for every block
    for i in range(total_blocks):
        # Calculate all of the cipher text as an integer
        C0 = int(BitVector(hexstring=encrypted_text_list[0][i*64:i*64 + 64]))
        C1 = int(BitVector(hexstring=encrypted_text_list[1][i*64:i*64 + 64]))
        C2 = int(BitVector(hexstring=encrypted_text_list[2][i*64:i*64 + 64]))

        # Calculate plain text
        M3 = (C0*N0*N0i + C1*N1*N1i + C2*N2*N2i) % N
        M = BitVector(intVal=solve_pRoot(e, M3), size=256)
        total_M += M

    return total_M.get_bitvector_in_ascii()

if __name__ == '__main__':
    if len(sys.argv) == 3:
        e = 3 # set e as constant

        # set up constants and values for the original message encryption
        message_file = open(sys.argv[1], 'r')
        message = message_file.read()
        message_file.close()
        while (len(message) % 16) != 0:
            message = message + '\0'
        prepend = '\0'*16
        generator = PrimeGenerator(bits=128)

        # find p, q, and n values for all three encryptions
        n_list = []
        for i in range(3):
            p = generator.findPrime()
            q = generator.findPrime()
            while p == q or gcd(p - 1, e) != 1 or gcd(q - 1, e) != 1:
                p = generator.findPrime()
                q = generator.findPrime()
            n = p*q
            n_list.append(n)

        # set up lists
        encrypted_text_list = []
        encrypted_text_names = ['encrypted0', 'encrypted1', 'encrypted2']

        # calculate encrypted text and save it to list
        for an_n in n_list:
            encrypted_text = ''
            for i in range(len(message)//16):
                c_block = int(BitVector(textstring=(prepend + message[16 * i:16 * i + 16])))
                c_block = exp_mod(c_block, e, an_n)
                c_block = BitVector(intVal=c_block, size=256)
                encrypted_text += c_block.getHexStringFromBitVector()
            encrypted_text_list.append(encrypted_text)

        # write encrypted text to files
        for j in range(len(encrypted_text_names)):
            e_file = open(encrypted_text_names[j], 'w')
            e_file.write(encrypted_text_list[j])
            e_file.write('\n' + 'n value is: ' + str(n_list[j]))
            e_file.close()

        # find cracked message and write it to a file
        cracked_message = find_message(encrypted_text_list, n_list, e)
        cracked_file = open(sys.argv[2], 'w')
        cracked_file.write(cracked_message)
        cracked_file.close()

    # error handling
    else:
        raise ValueError('Must have 2 parameters as files')
