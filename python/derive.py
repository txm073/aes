import hashlib
import numpy as np
from aes import utils
from aes.constants import *
import os

def generate_round_key(prev_key, round_num):
    """ Generate a round key based on the previous round key """
    # Calculate first column
    col = prev_key[:, 3].tolist()
    col.append(col[0])
    del col[0]
    for i in range(4):
        val = col[i]
        col[i] = SUBBOX[val // 16][val % 16]
    #print_as_hex([col])
    first_col = [x ^ y ^ z for x, y, z in zip(prev_key[:, 0].tolist(), col, RCON[round_num])]    
    # Iterate over previous columns in the key matrix 
    # Compute next column in the output key by: 
    #   ([n] equivalent to subscript (n)) 
    #   col[n + 1] = col[n] XOR col[n - 2]
    col_resultant = first_col
    output = [col_resultant]
    for i in range(1, 4):
        col = prev_key[:, i]
        col_resultant = utils.xor_array(col, col_resultant)
        output.append(col_resultant)
    return utils.rows_to_cols(output)

def expand_key(key):
    """ Take a 128-bit cipher key and create 10 additional keys for each round """
    round_keys = [key]
    for i in range(ROUNDS):
        round_key = generate_round_key(round_keys[-1], i)
        round_keys.append(round_key)
    return round_keys

def derive_key(password=None):
    if not password:
        return list(os.urandom(16))
    hash = list(hashlib.sha256(password.encode()).digest())
    return [hash[i] ^ hash[i + 1] for i in range(0, len(hash), 2)]

    