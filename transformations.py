'''
transformations.py
    - add_round_key(state, round_key)
    - sub_bytes(state)
    - shift_rows(state)
    - mix_columns(state)
'''

# Performs the AES AddRoundKey transformation.
def add_round_key (state, round_key):
    for i in range (4):
        for j in range (4):
            state [i][j] ^= round_key [i][j]

    return state