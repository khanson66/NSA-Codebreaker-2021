import hashlib
import sys
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox

# decodeing encrypted stream for every packet but the first 2 which use plaintext and private key encoding


text = [1615896210, "c08997c1fe9934b5522f6a7658c608fd34053df7b91007c277dc23be36b9bef292103506557557a63fdcabd7cf91a55cdfec6cb473b85b098408e7115e5c2edeb075640757a5b4b79290"],
[1615896250, "3a2acf6188c7e71ae120281b902efd0bcb314c41b7893d1b0c2c9cec591e5656ab3aecc4f8c1cfa0522d59c00883bdbdc69203e773cf3a6297fa7c702b8e89293e3cff70f5cf3b32287c"]

uname = sys.argv[1]
ver = 10

for i in range(0, ver):
    for j in range(0, ver):
        for k in range(0, ver):
            for m in range(0, ver):
                ver_num = str(i) + "." + str(j) + "." + str(k) + "." + str(m)
                for t in text:
                    #nonce = bytes.fromhex(str(t[1][8:56]))
                    ciphertext = bytes.fromhex(str(t[1]))
                    key = uname + "+" + ver_num + "+" + str(t[0])
                    session_key = hashlib.sha256(key.encode('utf-8')).digest()
                    box = SecretBox(key=session_key)
                    try:
                        out = box.decrypt(ciphertext=ciphertext)
                    except CryptoError:
                        continue
                    with open("results.txt", "a") as f:
                        f.write(f'key = {key}')
                        f.write(f'session-key = {bytes.hex(session_key)}')
                        f.write(f'{str(t[1][56:])}')
                        f.write(bytes.hex(out))
                    
                        
