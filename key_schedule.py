'''
Implements the AES key schedule (Key Expansion).
This module provides functions to generate all round keys from the
original AES key. It produces the full sequence of 4-byte words 
used as round keys for AES-128, AES-192, and AES-256 encryption.
'''

from constants import S_BOX, RCON

# Performs a cyclic left rotation of a 4-byte word.
def rot_word (word):
    return word [1:] + word [:1]

# Applies the AES S-box to each byte of a 4-byte word.
def sub_word (word):
    return [S_BOX [byte] for byte in word]

# Expands the original AES key into the full set of round keys.
def expand_key (key):
    w = []
    Nk = len (key) // 4
    Nr = Nk + 6

    for i in range (Nk):
        w.append (key [4 * i:4 * i + 4])

    for i in range (Nk, 4 * Nr + 4):    
        temp = w [i - 1]
                
        if i % Nk == 0:
            temp = sub_word (rot_word (temp))
            temp [0] ^= RCON [i // Nk]
        elif Nk > 6 and i % Nk == 4:
            temp = sub_word (temp)
    
        w.append (xor_words (w [i - Nk], temp))
    
    return w

# Performs an element-wise XOR of two 4-byte words.
def xor_words (a, b):
    return [x ^ y for x, y in zip (a, b)]