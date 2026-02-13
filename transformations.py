'''
Implements the core AES state transformations.
This module provides functions that operate on the 4x4 state matrix,
including AddRoundKey, SubBytes, ShiftRows, and MixColumns.
These transformations implement the round operations of AES
as defined in FIPS-197 and are used in every encryption round.
'''

from constants import S_BOX
from gf import gf_multiply

# Performs the AES AddRoundKey transformation.
def add_round_key (state, round_key):
    for i in range (4):
        for j in range (4):
            state [i][j] ^= round_key [i][j]

    return state

# Performs the AES SubBytes step on the given 4x4 state matrix.
def sub_bytes (state):
    for i in range (4):
        for j in range (4):
            state [i][j] = S_BOX [state [i][j]]

    return state

# Performs the AES ShiftRows step on the 4x4 state matrix.
def shift_rows (state):
    state [1][0], state [1][1], state [1][2], state [1][3] = state [1][1], state [1][2], state [1][3], state [1][0]
    state [2][0], state [2][1], state [2][2], state [2][3] = state [2][2], state [2][3], state [2][0], state [2][1]
    state [3][0], state [3][1], state [3][2], state [3][3] = state [3][3], state [3][0], state [3][1], state [3][2] 
    return state

# Performs the AES MixColumns step on the 4x4 state matrix.
def mix_columns (state):
    for i in range (4):
        a = state [0][i]
        b = state [1][i]
        c = state [2][i]
        d = state [3][i]

        state [0][i] = gf_multiply (a, 2) ^ gf_multiply (b, 3) ^ c ^ d
        state [1][i] = a ^ gf_multiply (b, 2) ^ gf_multiply (c, 3) ^ d
        state [2][i] = a ^ b ^ gf_multiply (c, 2) ^ gf_multiply (d, 3)
        state [3][i] = gf_multiply (a, 3) ^ b ^ c ^ gf_multiply (d, 2)

    return state