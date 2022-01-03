import numpy as np
from aes.constants import *

def xor_array(*arrays):
    """ Performs an XOR operation on each element of multiple arrays """
    return [i ^ j for i, j in zip(*arrays)]

def xor_sum(arr):
    """ Performs a cumulative XOR operation on an array """
    output = arr[0]
    for n in arr[1:]:
        output ^= n
    return output

def rows_to_cols(mat):
    """ Used to rearrange a 4x4 row-wise matrix as a 4x4 matrix column-wise """ 
    return np.array([[mat[i][j] for i in range(4)] for j in range(4)])
    
def create_matrix(arr):
    """ Create a 4x4 column-wise matrix from a 16x1 array """
    assert len(arr) == 16, "Array must have 16 elements"
    output = np.empty([4, 4], dtype=np.uint16)
    for i in range(0, 16, 4):
        output[:, i // 4] = arr[i:i+4]
    return output

def to_plaintext(data):
    """ Convert a 4x4 matrix into a string of ASCII characters (decryption postprocessing) """
    output = ""
    for i in range(4):
        for j in range(4):
            output += chr(data[j][i])
    return output

def reformat(data):    
    """ Convert a 4x4 matrix of integers into a string of hex values concatenated with a colon """
    output = ""
    for i in range(4):
        for j in data[:, i]:
            output += hex(j)
    return output

def pad(data):
    """ Pad the data array to be divisible by 16 and can be truncated every 128-bits """
    while len(data) % 16:
        data += data[:(16 - len(data) % 16)]
    return data

def hex(i):
    """ Convert 8-bit decimal number into a hexadecimal digit always made up of 2 characters """
    x, y = str(i // 16), str(i % 16)
    for old, new in [("10", "A"), ("11", "B"), ("12", "C"), ("13", "D"), ("14", "E"), ("15", "F")]:
        x = x.replace(old, new)
        y = y.replace(old, new)
    return x + y

def get_blocks(data):
    """ Yield 128-bit blocks of data """
    for i in range(0, len(data), 16):
        yield data[i:i+16]    

