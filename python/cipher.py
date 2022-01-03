import numpy as np
import random
from aes import utils
from aes.constants import *

def shift_rows(data, inverse=False):
    for i in range(4):
        array = data[i].tolist()
        for j in range(i if not inverse else (4 - i)):
            array.append(array[0])
            del array[0]
        data[i] = array
    return data

def add_round_key(data, round_key):
    for i in range(4):
        data[:, i] = utils.xor_array(data[:, i], round_key[:, i])
    return data

def lookup(n, table, inverse=False):
    if not inverse:
        return table[n // 16][n % 16]
    for i in range(len(table)):
        for j in range(len(table[i])):
            if table[i][j] == n:
                return i * 16 + j

def sub_bytes(data, inverse=False):
    for i in range(4):
        for j in range(4):
            data[j][i] = lookup(data[j][i], SUBBOX, inverse=inverse)
    return data

def transform(i, j):
    if j == 1:
        return i    
    if j == 2:
        return ((i << 1) ^ 0x1b) % 256
    if j == 3:
        return transform(i, 2) ^ i
    if j == 9:
        return transform(transform(transform(i, 2), 2), 2) ^ i
    if j == 11:
        return transform(transform(transform(i, 2), 2) ^ i, 2) ^ i 
    if j == 13:
        return transform(transform(transform(i, 2) ^ i, 2), 2) ^ i
    if j == 14:
        return transform(transform(transform(i, 2) ^ i, 2) ^ i, 2)

def mix_columns(data, inverse=False):
    mat = MIXCOLS if not inverse else MIXCOLS_INV
    output = np.empty([4, 4], dtype=int)
    for i in range(4):
        for j in range(4):  
            row, col = mat[i], data[:, j]
            arr = [transform(j, i) for i, j in zip(row, col)]
            output[i][j] = utils.xor_sum(arr)  
    return output

def round(data, roundkey, mixcols=True):
    data = sub_bytes(data)
    data = shift_rows(data)
    if mixcols:
        data = mix_columns(data)
    data = add_round_key(data, roundkey)
    return data

def round_inverse(data, roundkey, mixcols=True):
    data = add_round_key(data, roundkey)
    if mixcols:
        data = mix_columns(data, inverse=True) 
    data = shift_rows(data, inverse=True)
    data = sub_bytes(data, inverse=True)
    return data

def rijndael_cipher(data, rkeys):
    data = add_round_key(data, rkeys[0])
    for i in range(1, ROUNDS + 1):
        mixcols = (i != ROUNDS)
        data = round(data, rkeys[i], mixcols)
    return data

def rijndael_inverse(data, rkeys):
    for i in range(ROUNDS):
        mixcols = bool(i)
        data = round_inverse(data, rkeys[ROUNDS - i], mixcols)
    data = add_round_key(data, rkeys[0])
    return data

