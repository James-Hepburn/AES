'''
transformations.py
    - add_round_key(state, round_key)
    - sub_bytes(state)
    - shift_rows(state)
    - mix_columns(state)
'''

from constants import S_BOX

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