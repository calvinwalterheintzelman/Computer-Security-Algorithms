# Calvin Walter Heintzelman
# Using python verson 3.7.2

import sys
from BitVector import *

PassPhrase = "Hopes and dreams of a million years"

BLOCKSIZE = 16
numbytes = BLOCKSIZE // 8 # 2 total bytes

bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)
for i in range(0,len(PassPhrase) // numbytes):
    textstr = PassPhrase[i * numbytes:(i + 1) * numbytes]
    bv_iv ^= BitVector(textstring=textstr)

FILEIN = open("encrypted.txt")
encrypted_bv = BitVector( hexstring = FILEIN.read() )

success = False # checks

for l in range(48, 127): # ASCII values of reasonable characters
    for k in range(48, 127): # ASCII values of reasonable characters

        key = chr(l) + chr(k) # concatenates string

        key = key.strip()

        key_bv = BitVector(bitlist = [0]*BLOCKSIZE)
        for i in range(0,len(key) // numbytes):
            keyblock = key[i*numbytes:(i+1)*numbytes]
            key_bv ^= BitVector(textstring=keyblock)

        msg_decrypted_bv = BitVector( size = 0 )

        previous_decrypted_block = bv_iv
        for i in range(0, len(encrypted_bv) // BLOCKSIZE):
            bv = encrypted_bv[i * BLOCKSIZE:(i + 1) * BLOCKSIZE]
            temp = bv.deep_copy()
            bv ^= previous_decrypted_block
            previous_decrypted_block = temp
            bv ^= key_bv
            msg_decrypted_bv += bv

        outputtext = msg_decrypted_bv.get_text_from_bitvector()

        if "Cormac McCarthy" in outputtext: # checks if output is sensible
            print(key)
            success = True # exits loop if true
            break
    if success == True: # exits loop if true
        break

# Write to file
FILEOUT = open("decrypted_text.txt", 'w')
FILEOUT.write(outputtext)
FILEOUT.close()

# The encryption key is "iv"

