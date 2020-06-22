# Using python verson 3.7.2

import sys
from BitVector import *

if len(sys.argv) is not 3:
    sys.exit('''Needs two command-line arguments, one for '''
             '''the encrypted file and the other for the'''
             '''decrypted output file''')

PassPhrase = "Hopes and dreams of a million years"

BLOCKSIZE = 16
numbytes = BLOCKSIZE // 8 # 2 total bytes

bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)
for i in range(0,len(PassPhrase) // numbytes):
    textstr = PassPhrase[i * numbytes:(i + 1) * numbytes]
    bv_iv ^= BitVector(textstring=textstr)

FILEIN = open(sys.argv[1])
encrypted_bv = BitVector( hexstring = FILEIN.read() )

key = None
if sys.version_info[0] == 3:
    key = input("\nEnter key: ")
else:
    key = raw_input("\nEnter key: ")
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

FILEOUT = open(sys.argv[2], 'w')
FILEOUT.write(outputtext)
FILEOUT.close()