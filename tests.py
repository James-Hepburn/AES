'''
Step-by-step unit tests for AES-128.
Each AES transformation and the key schedule is tested 
individually using small examples and official NIST vectors.
'''

from state import create_state, state_to_bytes, pretty_print
from transformations import add_round_key, sub_bytes, shift_rows, mix_columns, inv_sub_bytes, inv_shift_rows, inv_mix_columns
from key_schedule import expand_key
from main import words_to_round_keys, encrypt, decrypt

# State representation tests
def test_state_conversion ():
    print ("Testing state conversion...")
    plaintext = [i for i in range (16)]
    state = create_state (plaintext)
    round_trip = state_to_bytes (state)
    assert round_trip == plaintext, f"State conversion failed! {round_trip}"
    print ("State conversion passed.")

# SubBytes test
def test_sub_bytes ():
    print ("Testing SubBytes...")
    state = create_state ([0x00] * 16)
    transformed = sub_bytes (state)
    for row in transformed:
        for byte in row:
            assert byte == 0x63, f"SubBytes failed! Got {byte}"
    print ("SubBytes passed.")

# ShiftRows test
def test_shift_rows ():
    print ("Testing ShiftRows...")
    state = create_state (list (range (16)))
    shifted = shift_rows (state)
    pretty_print (shifted)
    print ("ShiftRows visual check done.")

# MixColumns test
def test_mix_columns ():
    print ("Testing MixColumns...")
    state = create_state ([0xdb,0x13,0x53,0x45, 0,0,0,0,0,0,0,0,0,0,0,0])
    mixed = mix_columns (state)
    first_col = [mixed [i][0] for i in range (4)]
    expected = [0x8e,0x4d,0xa1,0xbc]
    assert first_col == expected, f"MixColumns failed! Got {first_col}"
    print ("MixColumns passed.")

# AddRoundKey test
def test_add_round_key ():
    print ("Testing AddRoundKey...")
    state = create_state ([0x00]*16)
    key_state = create_state ([0xff]*16)
    result = add_round_key (state, key_state)
    assert all (byte == 0xff for row in result for byte in row), f"AddRoundKey failed! {result}"
    print ("AddRoundKey passed.")

# Key Expansion test
def test_key_expansion ():
    print ("Testing key expansion...")
    key = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]
    expanded = expand_key (key)
    round_keys = words_to_round_keys (expanded)
    assert len(round_keys) == 11, f"Key expansion failed, got {len (round_keys)} round keys"
    print ("Key expansion passed.")

# Full encryption test
def test_full_encryption ():
    print ("Testing full AES-128 encryption...")
    key = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]
    plaintext = [0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34]
    expected_ciphertext = [0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32]
    ciphertext = encrypt (plaintext, key)
    assert ciphertext == expected_ciphertext, f"Full encryption failed! Got {ciphertext}"
    print ("Full encryption passed!")

# Inverse transformations tests
def test_inv_sub_bytes ():
    print ("Testing InvSubBytes...")
    state = create_state ([0x63] * 16)  
    transformed = inv_sub_bytes (state)
    for row in transformed:
        for byte in row:
            assert byte == 0x00, f"InvSubBytes failed! Got {byte}"
    print ("InvSubBytes passed.")

def test_inv_shift_rows ():
    print ("Testing InvShiftRows...")
    state = create_state (list (range (16)))
    shifted = inv_shift_rows (state)
    pretty_print (shifted)
    print ("InvShiftRows visual check done.")

def test_inv_mix_columns ():
    print ("Testing InvMixColumns...")
    state = create_state ([0x8e,0x4d,0xa1,0xbc, 0,0,0,0,0,0,0,0,0,0,0,0])
    inv_mixed = inv_mix_columns (state)
    first_col = [inv_mixed [i][0] for i in range (4)]
    expected = [0xdb,0x13,0x53,0x45]  
    assert first_col == expected, f"InvMixColumns failed! Got {first_col}"
    print ("InvMixColumns passed.")

# Full decryption test
def test_full_decryption ():
    print ("Testing full AES-128 decryption...")
    key = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]
    plaintext = [0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34]
    ciphertext = encrypt (plaintext, key)
    decrypted = decrypt (ciphertext, key)
    assert decrypted == plaintext, f"Full decryption failed! Got {decrypted}"
    print ("Full decryption passed!")

# Run all tests
if __name__ == "__main__":
    test_state_conversion ()
    test_sub_bytes ()
    test_shift_rows ()
    test_mix_columns ()
    test_add_round_key ()
    test_key_expansion ()
    test_full_encryption ()
    test_inv_sub_bytes ()
    test_inv_shift_rows ()
    test_inv_mix_columns ()
    test_full_decryption ()
    print ("\nAll AES tests completed successfully!")