#!/usr/bin/env python3

# Homework Number: 7
# Name: Calvin Walter Heintzelman
# ECN Login: cheintze
# Due Date: 3/07/2019

# Using python version 3.7.2
# sha512.py

import os
import sys
from BitVector import *

# list of constants used for hashing
Ki_list = \
    [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
     0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
     0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
     0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
     0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
     0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
     0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
     0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
     0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
     0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
     0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
     0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
     0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
     0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
     0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
     0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]


# function used to create message schedule
def sigma0(x):
    return (x.deep_copy() >> 1) ^ (x.deep_copy() >> 8) ^ x.deep_copy().shift_right(7)


# function used to create message schedule
def sigma1(x):
    return (x.deep_copy() >> 19) ^ (x.deep_copy() >> 61) ^ x.deep_copy().shift_right(6)


if __name__ == '__main__':
    if len(sys.argv) == 3:
        # open and read input file
        input_f = open(sys.argv[1], 'r')
        Input = input_f.read()
        input_f.close()

        # append the input so that it's a multiple of 1024
        input_len = len(Input) * 8
        total_0_append_bits = 1024 - ((input_len + 128 + 1) % 1024)  # finds number of 0 bits to append
        bits_0 = BitVector(intVal=0, size=total_0_append_bits)
        input_len_bits = BitVector(intVal=input_len, size=128)
        one_bit = BitVector(intVal=1, size=1)
        input_bits = BitVector(textstring=Input)
        appended_input = input_bits + one_bit + bits_0 + input_len_bits

        # set in initial constant values
        a = BitVector(hexstring='6a09e667f3bcc908')
        b = BitVector(hexstring='bb67ae8584caa73b')
        c = BitVector(hexstring='3c6ef372fe94f82b')
        d = BitVector(hexstring='a54ff53a5f1d36f1')
        e = BitVector(hexstring='510e527fade682d1')
        f = BitVector(hexstring='9b05688c2b3e6c1f')
        g = BitVector(hexstring='1f83d9abfb41bd6b')
        h = BitVector(hexstring='5be0cd19137e2179')

        mes_sch = [i for i in range(80)]  # creates list of length 80 for message schedule

        # for every 1024 bit block
        for i in range(len(appended_input) // 1024):
            block = appended_input[i*1024:i*1024 + 1024]  # calculates block

            # gets the first 16 words in message schedule from the block
            for j in range(16):
                mes_sch[j] = block[64*j:64*j + 64]
            # gets the rest of the words in message schedule from complicated formula
            for j in range(80 - 16):
                mes_sch[j+16] = BitVector(intVal=(int(mes_sch[j]) + int(sigma0(mes_sch[j+1])) + int(mes_sch[j+9]) +
                                                  int(sigma1(mes_sch[j+14]))) % 18446744073709551616, size=64)

            # create copies of constants
            a_copy = a.deep_copy()
            b_copy = b.deep_copy()
            c_copy = c.deep_copy()
            d_copy = d.deep_copy()
            e_copy = e.deep_copy()
            f_copy = f.deep_copy()
            g_copy = g.deep_copy()
            h_copy = h.deep_copy()

            # The 80 rounds of processing for this block
            for t in range(80):
                # Calculates T1 and T2 so that constants a and e can be properly redefined
                Chefg = (e_copy & f_copy) ^ (~e_copy & g_copy)
                Majabc = (a_copy & b_copy) ^ (a_copy & c_copy) ^ (b_copy & c_copy)
                sum_a = (a_copy.deep_copy() >> 28) ^ (a_copy.deep_copy() >> 34) ^ (a_copy.deep_copy() >> 39)
                sum_e = (e_copy.deep_copy() >> 14) ^ (e_copy.deep_copy() >> 18) ^ (e_copy.deep_copy() >> 41)
                T1 = (int(h_copy) + int(Chefg) + int(sum_e) + int(mes_sch[t]) + int(Ki_list[t])) % 18446744073709551616
                T2 = (int(sum_a) + int(Majabc)) % 18446744073709551616

                # redefines all of the copies of the constants
                h_copy = g_copy.deep_copy()
                g_copy = f_copy.deep_copy()
                f_copy = e_copy.deep_copy()
                e_copy = BitVector(intVal=(int(d_copy) + T1) % 18446744073709551616, size=64)
                d_copy = c_copy.deep_copy()
                c_copy = b_copy.deep_copy()
                b_copy = a_copy.deep_copy()
                a_copy = BitVector(intVal=(T1 + T2) % 18446744073709551616, size=64)

            # calculates the new values of the constant for the final hash or for the next block to be processed
            a = BitVector(intVal=(int(a) + int(a_copy)) % 18446744073709551616, size=64)
            b = BitVector(intVal=(int(b) + int(b_copy)) % 18446744073709551616, size=64)
            c = BitVector(intVal=(int(c) + int(c_copy)) % 18446744073709551616, size=64)
            d = BitVector(intVal=(int(d) + int(d_copy)) % 18446744073709551616, size=64)
            e = BitVector(intVal=(int(e) + int(e_copy)) % 18446744073709551616, size=64)
            f = BitVector(intVal=(int(f) + int(f_copy)) % 18446744073709551616, size=64)
            g = BitVector(intVal=(int(g) + int(g_copy)) % 18446744073709551616, size=64)
            h = BitVector(intVal=(int(h) + int(h_copy)) % 18446744073709551616, size=64)

        '''
        After all blocks are processed, this opens the output file and writes the constants
        to the file in the proper order, thus finishing the calculation of the hash value '''
        output_f = open(sys.argv[2], 'w')
        output_f.write(a.getHexStringFromBitVector())
        output_f.write(b.getHexStringFromBitVector())
        output_f.write(c.getHexStringFromBitVector())
        output_f.write(d.getHexStringFromBitVector())
        output_f.write(e.getHexStringFromBitVector())
        output_f.write(f.getHexStringFromBitVector())
        output_f.write(g.getHexStringFromBitVector())
        output_f.write(h.getHexStringFromBitVector())
        output_f.close()

    else:
        # only occurs if the script is called incorrectly
        raise ValueError("Must have 2 parameters")
