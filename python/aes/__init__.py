import numpy as np
import base64

from .constants import *
from .utils import *
from .cipher import *
from .derive import *

__dir__ = lambda: ["encrypt", "decrypt", "encrypt_file", "decrypt_file"]


class Error(Exception):
    pass


def _assert(stmt, msg, code=0, err=Error):    
    code = f"[{code}]:" if code else ""
    if not stmt:
        raise err(code + msg)

def encrypt(data, password=None, output_mode="hex", rlevel=0):
    """ Encrypt string data using the AES-128 bit algorithm """
    _assert(data, "Provide some data to encrypt")
    dtype = type(data).__name__
    padding = 16 - len(data) % 16
    enc = ""
    # If a password is provided then encrypt it with itself once (max recursion depth of 1) and append to the the metadata
    if password:
        if not rlevel:
            enc = encrypt(data=password, password=password, rlevel=1)
    
    # Add metadata to the start of the output
    output = hex(padding) + hex(0 if dtype == "bytes" else 1) + enc + (HEADER_CHAR if not rlevel else "")

    data = pad(data)
    key = derive_key(password=password)
    key = create_matrix(key)
    rkeys = expand_key(key)
    
    for block in get_blocks(data):
        block = create_matrix([ord(char) for char in block] if dtype == "str" else list(block))
        cipher_block = rijndael_cipher(block, rkeys)
        output += reformat(cipher_block)
    
    if output_mode == "base64":
        output = base64.b64encode(output.encode()).decode()
    if output_mode == "base64-bytes":
        output = base64.b64encode(output.encode())

    if not password:
        return output, to_plaintext(key)
    
    return output
  
def decrypt(data, password=None, key=None, input_mode="hex", rlevel=0):
    """ Decrypt a string that has been encrypted with AES-128 """
    _assert(bool(password) ^ bool(key), "Provide either a password or a 128-bit encryption key")

    if input_mode == "base64":
        data = base64.b64decode(data.encode()).decode()
    if input_mode == "base64-bytes":
        data = base64.b64decode(data).decode()

    if password:
        key = derive_key(password=password)
    else:
        key = [ord(char) for char in key]

    key = create_matrix(key)
    rkeys = expand_key(key)
    
    output = ""
    if not rlevel:
        headers, data = data.split(HEADER_CHAR)
    else:
        headers = data
    data = [int(data[i:i+2], base=16) for i in range(0, len(data), 2)]
    
    padding = int(headers[:2], base=16)
    # Determine whether to output string or bytes
    as_bytes = not bool(int(headers[2:4], base=16))
    if password:
        password_enc = headers[4:]
        if not rlevel:
            decrypted_header = decrypt(data=password_enc, password=password, rlevel=1)
            _assert(decrypted_header == password, "Invalid decryption password")    

    for block in get_blocks(data if not rlevel else data[2:]):
        block = create_matrix(block)
        deciphered = rijndael_inverse(block, rkeys)
        output += to_plaintext(deciphered)

    if as_bytes:
        output = output.encode()

    if padding:
        output = output[:-padding]

    return output

def encrypt_file(file, password, line_length=80):
    """ Encrypt a file with AES-128 encryption """
    with open(file, "rb") as f:
        data = f.read()
    enc = encrypt(data, password=password, output_mode="base64-bytes")
    length = len(enc)
    with open(file, "wb") as f:
        for i in range(0, length, line_length):
            if i + line_length < length:
                f.write(enc[i:i+line_length] + b"\n")
            else:
                f.write(enc[i:] + b"\n")

def decrypt_file(file, password):
    """ Decrypt a file with AES-128 encryption """
    with open(file, "rb") as f:
        enc = b"".join(f.readlines())
    data = decrypt(enc, password=password, input_mode="base64-bytes")
    with open(file, "wb") as f:
        f.write(data)