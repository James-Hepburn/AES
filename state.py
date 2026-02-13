'''
Implements the AES state representation.
The AES state is a 4x4 byte matrix stored in column-major order.
This module provides functions to convert between a 16-byte block 
and the internal 4x4 state format.
'''

# Converting a 16-byte input block into the AES 4x4 state matrix using 
# column-major order as defined in FIPS-197.
def create_state (bytes):
    state = [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ]

    for i in range (4):
        for j in range (4):
            state [i][j] = bytes [j * 4 + i]

    return state

# Converts the AES 4x4 state matrix back into a 16-byte block using column-major order.
def state_to_bytes (state):
    bytes = [0] * 16

    for i in range (4):
        for j in range (4):
            bytes [j * 4 + i] = state [i][j]

    return bytes

# Prints the AES state row-by-row for debugging purposes.
def pretty_print (state):
    for i in range (4):
        print (state [i])