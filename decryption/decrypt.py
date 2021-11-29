import hashlib
from nacl.utils import EncryptedMessage
import numpy
import os
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, Box, EncryptedMessage

plaintext = b'a'


aprivate = PrivateKey(bytes.fromhex("c53fec9cac3927105979b09a94ee03511e93c7c25e6de00b7a23dd5f6ff8b8f5"))
apublic = aprivate.public_key
    
bprivate = PrivateKey(bytes.fromhex("022f377b17e041c037e7877df43567eedeb5d46bad3879d06fd714b1cda65cee"))
bpublic = bprivate.public_key
#print(bytes.hex(private._private_key))
#print(bytes.hex(public._public_key))
nonce = bytes.fromhex("e640379b64deb0fcb43e80ff054d01370320dd8e31b5cc2e")

box = Box(aprivate,bpublic)

result = box.encrypt(plaintext=plaintext, nonce=nonce).ciphertext
print("===apublic===")
print(bytes.hex(aprivate._private_key))
print("===aprivate===")
print(bytes.hex(apublic._public_key))
print("===bpublic===")
print(bytes.hex(bprivate._private_key))
print("===bprivate===")
print(bytes.hex(bpublic._public_key))
print("===nonce===")
print(bytes.hex(nonce))
print("===plaintext===")
print(bytes.hex(plaintext))
print("===result===")
print(bytes.hex(result))