import pathlib
from ctypes import *
import os

path = str(pathlib.Path().absolute() / "lib.so")
if not os.path.exists(path):
    os.system("g++ -shared -o lib.so aes128.cpp")
lib = WinDLL(path)

def cast(obj):
    init = not type(obj) == type
    if isinstance(obj, tuple(c_int.__bases__[0].__subclasses__())): # already a C type
        return obj
    elif isinstance(obj, type(None)):
        return c_void_p
    elif isinstance(obj, int):
        return obj
    elif isinstance(obj, (str, type)):
        return c_char_p(obj.encode()) if init else c_char_p 
    elif isinstance(obj, (bytes, bytearray, type)):
        return c_byte(obj) if init else c_byte
    elif isinstance(obj, (float, type)):
        return c_float(obj) if init else c_float
    elif isinstance(obj, (bool, type)):
        return c_bool(obj) if init else c_bool
    else:
        return id(obj)

def generate_wrapper(fn, *, argc, argtypes, restype, default_args=None):
    if default_args is None:
        default_args = tuple()
    assert len(argtypes) == argc, "Provide a type for each parameter"
    fn.argtypes = tuple([cast(t) for t in argtypes])
    fn.restype = cast(restype)

    def wrapper(*args):
        defaults_required = argc - len(args)
        if defaults_required:
            args += default_args[-defaults_required:]
        print([cast(arg) for arg in args])  
        value = fn(*[cast(arg) for arg in args])
        print(value)
        if isinstance(value, (bytes, bytearray)) and restype is str:
            return value.decode()
        return value
    return wrapper

#encrypt = generate_wrapper(lib.encrypt, argc=3, argtypes=[str, str, str], restype=str, default_args=("hex",))
#decrypt = generate_wrapper(lib.decrypt, argc=3, argtypes=[str, str, str], restype=str, default_args=("hex",))
encrypt_file = generate_wrapper(lib.encryptFile, argc=3, argtypes=[str, str, int], restype=None)
decrypt_file = generate_wrapper(lib.decryptFile, argc=2, argtypes=[str, str], restype=None)

encrypt_file("./test.txt", "password123", 80)

"""
lib.test.restype = c_char_p
lib.test.argtypes = (c_char_p, )
string = lib.test(c_char_p(b"Hello World!")).decode()
print(dir(CDLL))
"""