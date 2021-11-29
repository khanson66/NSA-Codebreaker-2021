import hashlib
unames= "unknown","root"

for n in unames:
    for i in range(0,2):
        for j in range(0,9):
            for k in range(0,9):
                for l in range(0,9):
                    key=n+i+"."+j+"."+k+"."+l+"."+1615896179
                    bytes.hex(hashlib.sha256("+1.4.0.3+1615896179".encode('utf-8')).digest())