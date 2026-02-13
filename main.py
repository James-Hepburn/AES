'''
AES-128 encryption and decryption module.
Provides a simple interface to encrypt a single 16-byte plaintext block
using AES-128. It also includes a decryption function.
'''

from state import create_state, state_to_bytes
from transformations import add_round_key, sub_bytes, shift_rows, mix_columns, inv_sub_bytes, inv_shift_rows, inv_mix_columns
from key_schedule import expand_key

# Converts the list of 4-byte words from key expansion into
# 4x4 matrices representing each round key.
def words_to_round_keys (words):
    round_keys = []

    for i in range (0, len (words), 4):
        round_key = [[words [i + col][row] for col in range (4)] for row in range (4)]
        round_keys.append (round_key)

    return round_keys

# Encrypts a 16-byte plaintext block using AES-128.
def encrypt (plaintext, key):
    state = create_state (plaintext)
    expanded_key = expand_key (key)
    round_keys = words_to_round_keys (expanded_key)
    state = add_round_key (state, round_keys [0])

    for round in range (1, 10):
        state = sub_bytes (state)
        state = shift_rows (state)
        state = mix_columns (state)
        state = add_round_key (state, round_keys [round])

    state = sub_bytes (state)
    state = shift_rows (state)
    state = add_round_key (state, round_keys [10])

    return state_to_bytes (state)

# Decrypts a 16-byte AES-128 ciphertext block using the given key.
def decrypt (ciphertext, key):
    state = create_state (ciphertext)
    expanded_key = expand_key (key)
    round_keys = words_to_round_keys (expanded_key)

    state = add_round_key (state, round_keys [10])

    for round in range (9, 0, -1):
        state = inv_shift_rows (state)
        state = inv_sub_bytes (state)
        state = add_round_key (state, round_keys [round])
        state = inv_mix_columns (state)

    state = inv_shift_rows (state)
    state = inv_sub_bytes (state)
    state = add_round_key (state, round_keys [0])

    return state_to_bytes (state)