import aes
import os, sys
import getpass

try:
    os.chdir(os.path.dirname(sys.argv[0]))
except OSError:
    pass
aes.load_mixcols_table("aes/mixcols.pkl")
os.system("cls")
msg = input("Enter a message: ")
os.system("cls")
password = getpass.getpass("Enter a password: ")
enc = aes.encrypt(msg, password, output_mode="base64")
print("Encrypted message:", enc)
while True:    
    password = getpass.getpass("Enter your password to decrypt the message: ")
    try:
        original = aes.decrypt(enc, password, input_mode="base64")
    except aes.Error as e:
        print("Error:", e)
    else:
        break
print("Original message:", original)