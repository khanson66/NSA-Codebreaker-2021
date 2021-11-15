import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
import keys
import yf

enc_pub = PublicKey(public_key=keys.public_key)
enc_priv = PrivateKey(private_key=keys.client_sec)
encryptor = Box(public_key=enc_pub, private_key=enc_priv)
out = encryptor.decrypt(ciphertext=yf.ciphertext, nonce=yf.nonce)
print(out)
