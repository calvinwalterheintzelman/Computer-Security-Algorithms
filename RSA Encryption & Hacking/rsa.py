# ECE 404 Homework 6
# Calvin Walter Heintzelman
# cheintze
# 2/26/2019
# Using python version 3.7.2
# rsa.py

import os
import sys
import random
from BitVector import *

############## Kak's Code ##############
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

############## My Code ##############

def gcd(a, b): # finds GCD of a and b
    if a % b == 0:
        return b
    else:
        return gcd(b, a % b)

def exp_mod(text, exp, mod): # calculates text^exp % mod efficiently
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

e = 65537 # sets e as constant
# e and d are multiplicative inverses in mod (totient of n)
if __name__ == '__main__':
    # encryption algorithm
    if sys.argv[1] == '-e' and len(sys.argv) == 4:
        # sets up files and constants for encryption
        message_file = open(sys.argv[2], 'r')
        message = message_file.read()
        message_file.close()
        while (len(message) % 16) != 0:
            message = message + '\0'
        prepend = '\0'*16
        generator = PrimeGenerator(bits=128)

        # calculates the values of p and q
        p = generator.findPrime()
        q = generator.findPrime()
        while p == q or gcd(p-1, e) != 1 or gcd(q-1, e) != 1:
            p = generator.findPrime()
            q = generator.findPrime()

        # save p and q to files
        p_file = open('p.txt', 'w')
        p_file.write('The value of p is:\n' + str(p))
        p_file.close()
        q_file = open('q.txt', 'w')
        q_file.write('The value of q is:\n' + str(q))
        q_file.close()

        # find n and totient(n)
        n = p*q
        tot_n = (p-1)*(q-1)

        # outputs encrypted text to correct file
        encrypt = open(sys.argv[3], 'w')
        for i in range(len(message)//16):
            # calculate c_block
            c_block = int(BitVector(textstring=(prepend + message[16*i:16*i + 16])))
            c_block = exp_mod(c_block, e, n)
            c_block = BitVector(intVal=c_block, size=256)

            # output text
            output_text = c_block.getHexStringFromBitVector()
            encrypt.write(output_text)

        encrypt.close()

    # decryption algorithm
    elif sys.argv[1] == '-d' and len(sys.argv) == 4:
        # reads p and q from files
        p_file = open('p.txt', 'r')
        p_file.readline()
        p = int(p_file.readline())
        p_file.close()
        q_file = open('q.txt', 'r')
        q_file.readline()
        q = int(q_file.readline())
        q_file.close()

        # calculates n, totient(n), and d
        n = p*q
        tot_n = (p-1)*(q-1)
        d = int(BitVector(intVal=e).multiplicative_inverse(BitVector(intVal=tot_n)))

        # outputs d to its own file
        d_file = open('d.txt', 'w')
        d_file.write('The value of d is:\n' + str(d))
        d_file.close()

        # saves encrypted file as a string
        encrypt_file = open(sys.argv[2], 'r')
        encrypt = encrypt_file.read()
        encrypt_file.close()

        # outputs decrypted text to correct file
        decrypt_file = open(sys.argv[3], 'wb')
        for i in range(len(encrypt)//64):
            # reads block from cipher text
            c_block = int(BitVector(hexstring=encrypt[i*64:i*64 + 64]))

            # calculates constants using CRT and FLT
            Vp_exp = d % (p-1)
            Vq_exp = d % (q-1)
            Vp = exp_mod(c_block, Vp_exp, p)
            Vq = exp_mod(c_block, Vq_exp, q)
            Xp = q * int(BitVector(intVal=q).multiplicative_inverse(BitVector(intVal=p)))
            Xq = p * int(BitVector(intVal=p).multiplicative_inverse(BitVector(intVal=q)))

            # calculates decrypted text and saves it to file, deleting prepended '\0's
            c_block = (Vp*Xp + Vq*Xq) % n
            c_block = BitVector(intVal=c_block, size=256)
            c_block = c_block[128:256]
            c_block.write_to_file(decrypt_file)

        decrypt_file.close()

    # error handling
    else:
        raise ValueError('Must have 3 parameters and first parameter must be a "-e" or "-d"')
