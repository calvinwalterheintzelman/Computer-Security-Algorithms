# Homework Number 4
# Calvin Walter Heintzelman
# ECN Login: cheintze
# Due Date: 2/12/2019
# Using Python version 3.7.2
#
# NOTE: The encryption algorithm pads the message in message.txt with null characters if the total number of bytes
#       is not evenly divisible by 16. So the decrypted file will differ from the encrypted file only by some null
#       characters at the end, if at all. This does not change the meaning of the message, just the character count.

import os
import sys
from BitVector import *

##########################################
# Kak's Functions
AES_modulus = BitVector(bitstring='100011011')


def main(key):
    key_bv = BitVector(textstring=key)
    key_words = gen_key_schedule_256(key_bv)
    key_schedule = []

    for word_index, word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i * 8:i * 8 + 8].intValue())
        key_schedule.append(keyword_in_ints)
    num_rounds = 14
    round_keys = [None for i in range(num_rounds + 1)]
    for i in range(num_rounds + 1):
        round_keys[i] = (key_words[i * 4] + key_words[i * 4 + 1] + key_words[i * 4 + 2] + key_words[i * 4 + 3])
    return round_keys


def gee(keyword, round_constant, byte_sub_table):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size=0)
    for i in range(4):
        newword += BitVector(intVal=byte_sub_table[rotated_word[8 * i:8 * i + 8].intValue()], size=8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal=0x02), AES_modulus, 8)
    return newword, round_constant


def gen_key_schedule_256(key_bv):
    byte_sub_table = gen_subbytes_table()
    #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
    #  schedule. We will store all 60 keywords in the following list:
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal=0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i * 32: i * 32 + 32]
    for i in range(8, 60):
        if i % 8 == 0:
            kwd, round_constant = gee(key_words[i - 1], round_constant, byte_sub_table)
            key_words[i] = key_words[i - 8] ^ kwd
        elif (i - (i // 8) * 8) < 4:
            key_words[i] = key_words[i - 8] ^ key_words[i - 1]
        elif (i - (i // 8) * 8) == 4:
            key_words[i] = BitVector(size=0)
            for j in range(4):
                key_words[i] += BitVector(intVal=
                                          byte_sub_table[key_words[i - 1][8 * j:8 * j + 8].intValue()], size=8)
            key_words[i] ^= key_words[i - 8]
        elif ((i - (i // 8) * 8) > 4) and ((i - (i // 8) * 8) < 8):
            key_words[i] = key_words[i - 8] ^ key_words[i - 1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words


def gen_subbytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(0, 256):
        a = BitVector(intVal=i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        a1, a2, a3, a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable


def genTables():
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal=i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1, a2, a3, a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal=i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1, b2, b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))


##########################################

##########################################
# My function

def getByte(bits, num):
    return bits[num * 8:num * 8 + 8]

##########################################

message_file = open('message.txt', 'r')
message = message_file.read()
message_file.close()
key_file = open('key.txt', 'r')
key = key_file.read()
key_file.close()

# Pads the message in message.txt with null characters
more_chars = len(message) % 16
if more_chars != 0:
    for i in range(16 - more_chars):
        message += '\0'

round_keys = main(key)  # calculates all round keys for encryption/decryption

subBytesTable = []  # for encryption
invSubBytesTable = []  # for decryption
genTables()

# Encryption Algorithm

encrypt = ''
for i in range(len(message) // 16):  # for every 128 bit block
    text_block = message[i * 16:i * 16 + 16]
    bit_block = BitVector(textstring=text_block)
    bit_block = bit_block.__xor__(round_keys[0])  # pre-round XORing

    for j in range(len(round_keys) - 1):  # all rounds
        round_num = j + 1
        # substitute bytes
        for k in range(16):
            sub_val = subBytesTable[ord(bit_block[k * 8:k * 8 + 8].get_bitvector_in_ascii())]
            bit_block[k * 8:k * 8 + 8] = BitVector(size=8).__xor__(BitVector(intVal=sub_val))

        # shift rows; 12 total replacements

        # nothing done for row 0
        # row 1
        byte_num = 1
        temp = getByte(bit_block, 1)
        bit_block[byte_num * 8:byte_num * 8 + 8] = getByte(bit_block, 5)
        byte_num = 5
        bit_block[byte_num * 8:byte_num * 8 + 8] = getByte(bit_block, 9)
        byte_num = 9
        bit_block[byte_num * 8:byte_num * 8 + 8] = getByte(bit_block, 13)
        byte_num = 13
        bit_block[byte_num * 8:byte_num * 8 + 8] = temp

        # row 2
        byte_num = 2
        temp = getByte(bit_block, 2)
        bit_block[byte_num * 8:byte_num * 8 + 8] = getByte(bit_block, 10)
        byte_num = 10
        bit_block[byte_num * 8:byte_num * 8 + 8] = temp
        temp = getByte(bit_block, 6)
        byte_num = 6
        bit_block[byte_num * 8:byte_num * 8 + 8] = getByte(bit_block, 14)
        byte_num = 14
        bit_block[byte_num * 8:byte_num * 8 + 8] = temp

        # row 3
        byte_num = 3
        temp = getByte(bit_block, 3)
        bit_block[byte_num * 8:byte_num * 8 + 8] = getByte(bit_block, 15)
        byte_num = 15
        bit_block[byte_num * 8:byte_num * 8 + 8] = getByte(bit_block, 11)
        byte_num = 11
        bit_block[byte_num * 8:byte_num * 8 + 8] = getByte(bit_block, 7)
        byte_num = 7
        bit_block[byte_num * 8:byte_num * 8 + 8] = temp

        # mix cols
        if round_num != len(round_keys) - 1:
            bit_copy = []  # creates a 4 by 4 array of bit_block
            for k in range(4):
                inner = []
                for l in range(4):
                    inner.append(bit_block[32 * l + 8 * k:32 * l + 8 * k + 8])
                bit_copy.append(inner)

            for k in range(4):  # column 0
                bit_block[k * 8 * 4:k * 8 * 4 + 8] = (((
                    bit_copy[0][k].gf_multiply_modular(BitVector(bitstring='00000010'), AES_modulus, 8)).__xor__(
                    bit_copy[1][k].gf_multiply_modular(BitVector(bitstring='00000011'), AES_modulus, 8))).__xor__(
                    bit_copy[2][k])).__xor__(bit_copy[3][k])

            for k in range(4):  # column 1
                index = k * 8 * 4 + 8
                bit_block[index:index + 8] = (((
                    bit_copy[1][k].gf_multiply_modular(BitVector(bitstring='00000010'), AES_modulus, 8)).__xor__(
                    bit_copy[2][k].gf_multiply_modular(BitVector(bitstring='00000011'), AES_modulus, 8))).__xor__(
                    bit_copy[3][k])).__xor__(bit_copy[0][k])

            for k in range(4):  # column 2
                index = k * 8 * 4 + 16
                bit_block[index:index + 8] = (((
                    bit_copy[2][k].gf_multiply_modular(BitVector(bitstring='00000010'), AES_modulus, 8)).__xor__(
                    bit_copy[3][k].gf_multiply_modular(BitVector(bitstring='00000011'), AES_modulus, 8))).__xor__(
                    bit_copy[0][k])).__xor__(bit_copy[1][k])

            for k in range(4):  # column 3
                index = k * 8 * 4 + 24
                bit_block[index:index + 8] = (((
                    bit_copy[3][k].gf_multiply_modular(BitVector(bitstring='00000010'), AES_modulus, 8)).__xor__(
                    bit_copy[0][k].gf_multiply_modular(BitVector(bitstring='00000011'), AES_modulus, 8))).__xor__(
                    bit_copy[1][k])).__xor__(bit_copy[2][k])

        # add round key
        bit_block = bit_block.__xor__(round_keys[round_num])

    encrypt += bit_block.getHexStringFromBitVector()  # appends to encryption string

encrypt_file = open('encrypted.txt', 'w')
encrypt_file.write(encrypt)
encrypt_file.close()

# Decryption Algorithm

encrypt_file = open('encrypted.txt', 'r')
encrypted = encrypt_file.read()
encrypt_file.close()

encrypted = BitVector(hexstring=encrypted)
encrypted = encrypted.getTextFromBitVector()

decrypt = ''
for i in range(len(encrypted) // 16):  # for every 128 bit block
    text_block = encrypted[i * 16:i * 16 + 16]
    bit_block = BitVector(textstring=text_block)
    bit_block = bit_block.__xor__(round_keys[14])  # does pre-round XORing
    for j in range(len(round_keys) - 1):
        round_num = len(round_keys) - 2 - j  # rounds go in reverse order

        # inverse shift rows

        # row 0 does nothing
        # row 1
        byte_num = 1
        temp = getByte(bit_block, 1)
        bit_block[byte_num * 8:byte_num * 8 + 8] = getByte(bit_block, 13)
        byte_num = 13
        bit_block[byte_num * 8:byte_num * 8 + 8] = getByte(bit_block, 9)
        byte_num = 9
        bit_block[byte_num * 8:byte_num * 8 + 8] = getByte(bit_block, 5)
        byte_num = 5
        bit_block[byte_num * 8:byte_num * 8 + 8] = temp

        # row 2
        byte_num = 2
        temp = getByte(bit_block, 2)
        bit_block[byte_num * 8:byte_num * 8 + 8] = getByte(bit_block, 10)
        byte_num = 10
        bit_block[byte_num * 8:byte_num * 8 + 8] = temp
        temp = getByte(bit_block, 6)
        byte_num = 6
        bit_block[byte_num * 8:byte_num * 8 + 8] = getByte(bit_block, 14)
        byte_num = 14
        bit_block[byte_num * 8:byte_num * 8 + 8] = temp

        # row 3
        byte_num = 3
        temp = getByte(bit_block, 3)
        bit_block[byte_num * 8:byte_num * 8 + 8] = getByte(bit_block, 7)
        byte_num = 7
        bit_block[byte_num * 8:byte_num * 8 + 8] = getByte(bit_block, 11)
        byte_num = 11
        bit_block[byte_num * 8:byte_num * 8 + 8] = getByte(bit_block, 15)
        byte_num = 15
        bit_block[byte_num * 8:byte_num * 8 + 8] = temp

        # inverse substitute bytes
        for k in range(16):  # done for every byte
            sub_val = invSubBytesTable[ord(bit_block[k * 8:k * 8 + 8].get_bitvector_in_ascii())]
            bit_block[k * 8:k * 8 + 8] = BitVector(size=8).__xor__(BitVector(intVal=sub_val))

        # add round key
        bit_block = bit_block.__xor__(round_keys[round_num])

        # inverse mix columns
        if round_num != 0:
            bit_copy = []  # creates 4 by 4 array copy of bit_block
            for k in range(4):
                inner = []
                for l in range(4):
                    inner.append(bit_block[32 * l + 8 * k:32 * l + 8 * k + 8])
                bit_copy.append(inner)

            # start shifting columns
            for k in range(4):  # column 0
                bit_block[k * 8 * 4:k * 8 * 4 + 8] = (((
                    bit_copy[0][k].gf_multiply_modular(BitVector(bitstring='00001110'), AES_modulus, 8)).__xor__(
                    bit_copy[1][k].gf_multiply_modular(BitVector(bitstring='00001011'), AES_modulus, 8))).__xor__(
                    bit_copy[2][k].gf_multiply_modular(BitVector(bitstring='00001101'), AES_modulus, 8))).__xor__(
                    bit_copy[3][k].gf_multiply_modular(BitVector(bitstring='00001001'), AES_modulus, 8))

            for k in range(4):  # column 1
                index = k * 8 * 4 + 8
                bit_block[index:index + 8] = (((
                    bit_copy[0][k].gf_multiply_modular(BitVector(bitstring='00001001'), AES_modulus, 8)).__xor__(
                    bit_copy[1][k].gf_multiply_modular(BitVector(bitstring='00001110'), AES_modulus, 8))).__xor__(
                    bit_copy[2][k].gf_multiply_modular(BitVector(bitstring='00001011'), AES_modulus, 8))).__xor__(
                    bit_copy[3][k].gf_multiply_modular(BitVector(bitstring='00001101'), AES_modulus, 8))

            for k in range(4):  # column 2
                index = k * 8 * 4 + 16
                bit_block[index:index + 8] = (((
                    bit_copy[0][k].gf_multiply_modular(BitVector(bitstring='00001101'), AES_modulus, 8)).__xor__(
                    bit_copy[1][k].gf_multiply_modular(BitVector(bitstring='00001001'), AES_modulus, 8))).__xor__(
                    bit_copy[2][k].gf_multiply_modular(BitVector(bitstring='00001110'), AES_modulus, 8))).__xor__(
                    bit_copy[3][k].gf_multiply_modular(BitVector(bitstring='00001011'), AES_modulus, 8))

            for k in range(4):  # column 3
                index = k * 8 * 4 + 24
                bit_block[index:index + 8] = (((
                    bit_copy[0][k].gf_multiply_modular(BitVector(bitstring='00001011'), AES_modulus, 8)).__xor__(
                    bit_copy[1][k].gf_multiply_modular(BitVector(bitstring='00001101'), AES_modulus, 8))).__xor__(
                    bit_copy[2][k].gf_multiply_modular(BitVector(bitstring='00001001'), AES_modulus, 8))).__xor__(
                    bit_copy[3][k].gf_multiply_modular(BitVector(bitstring='00001110'), AES_modulus, 8))

    decrypt += bit_block.getTextFromBitVector()  # appends decrypt string

decrypt_file = open('decrypted.txt', 'w')
decrypt_file.write(decrypt)
decrypt_file.close()
