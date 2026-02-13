'''
Implements AES finite field (GF(2^8)) arithmetic.
This module provides functions to multiply bytes in GF(2^8)
according to the AES specification, including multiplication
by 2 (xtime) and general byte multiplication. 
'''

from constants import AES_POLY

# Multiply a byte by 2 in GF(2^8) using the AES polynomial.
def xtime (byte):
    if (byte & 0x80):
        return ((byte << 1) ^ AES_POLY) & 0xff

    return (byte << 1) & 0xff

# Multiply two bytes in GF(2^8) using the Russian peasant algorithm.
def gf_multiply (a, b):
    output = 0

    for i in range (8):
        if (b & 1):
            output ^= a

        a = xtime (a)
        b >>= 1
        a &= 0xff

    return output & 0xff