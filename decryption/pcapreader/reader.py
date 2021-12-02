import hashlib
from itertools import product
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, Box
from nacl.secret import SecretBox
import uuid

# decodeing encrypted stream for every packet but the first 2 which use plaintext and private key encoding
class Structure():
    MAGIC_START = bytes.fromhex("1DD0E1A4")
    MAGIC_END = bytes.fromhex("E6342401")


# each element of the packet that is defined is 2 bytes (bytes.fromhex("0000-bytes.fromhex("FFFF) exept the Structure with are 4 bytes
# Each section of the Packet orders as follows Param+Length+(Data/command)
class Params():
    PARAM_CMD = bytes.fromhex("5500")
    PARAM_UUID = bytes.fromhex("5508")
    PARAM_DIRNAME = bytes.fromhex("5514")
    PARAM_FILENAME = bytes.fromhex("551C")
    PARAM_CONTENTS = bytes.fromhex("5520")
    PARAM_MORE = bytes.fromhex("5524")
    PARAM_CODE = bytes.fromhex("5528")
    #GUESSES
    PARAM_RESPONSETASK = bytes.fromhex("5518")
    


class CMD():
    COMMAND_INIT = bytes.fromhex("0002") # For session init (give UUID)
    COMMAND_UPLOAD = bytes.fromhex("0006")
    COMMAND_FIN = bytes.fromhex("0007")
    #guesses
    COMMAND_INITTasking = bytes.fromhex("0003") # Possibley Get Tasking DIR
    COMMAND_GetTasking = bytes.fromhex("0004") # Possibley Get Tasking DIR
    COMMAND_DownloadData = bytes.fromhex("0005") # Possibley Get Tasking DIR



def create_secretbox(key):
    session_key = hashlib.sha256(key.encode('utf-8')).digest()
    box = SecretBox(key=session_key)
    return box

def decode(box, packet_data):
    
    container = str(packet_data[8:])
    ciphertext = bytes.fromhex(container)
  
    try:
        out = box.decrypt(ciphertext=ciphertext)
    except CryptoError:
        print("error: Cant decrypt SecretBox with given key")
        
    return out

def bytesToInt(byte_data):
    return int.from_bytes(byte_data, "big")

def toText(data):
    result = ""
    data_len = len(data) - 4 # subtracting to remove footer space header space accounted for
    
    #check if header is valid
    if data[0:4] != Structure.MAGIC_START:
        print("ERROR: INVAILD HEADER")
        print(Structure.MAGIC_START)
        return None
    #result += "MAGIC_START + "
    index=4
    while(True):
        #break if magic_ending
        if data[index:index+4] == Structure.MAGIC_END:
            break
        
        #safty break
        if index > len(data):
            print("ERROR: the packet had not clear ending")
            return None
        result += " + "
        param = data[index:index+2]
        index +=2 #move past param
        section_length = bytesToInt(data[index:index+2])
        index += 2 #move past length
        section_data = data[index:index+section_length]
        index += section_length
        match param:
            case Params.PARAM_CMD:
                result +="[COMMAND TO "
                match section_data:
                    case CMD.COMMAND_INIT:
                        result +=" INIT SESSION]"
                    case CMD.COMMAND_UPLOAD:
                        result += "UPLOAD DATA]"
                    case CMD.COMMAND_INITTasking:
                        result += " INIT Tasking]"
                    case CMD.COMMAND_GetTasking:
                        result += " Get Tasking]"
                    case CMD.COMMAND_DownloadData:
                        result += " DownLoad]"
                    case CMD.COMMAND_FIN:
                        result += " END SESSION]"
                    case CMD.COMMAND_FIN:
                        result += " END SESSION]"
                        
                    case _:
                        result += f" Command Not Found ({bytes.hex(section_data)})"
                        
                        
                    
            case Params.PARAM_UUID:
                guid = uuid.UUID(hex=bytes.hex(section_data))
                result += f"[UUID IS {guid} ]"
                
            case Params.PARAM_CONTENTS:
                contents = section_data[0:len(section_data)]
                result += f"[CONTENTS IN HEX ({contents}) ]"
                
            case Params.PARAM_MORE:
                contents = bytes.hex(section_data)
                result += f"[MORE {contents} ]"
                
            case Params.PARAM_DIRNAME:
                contents = section_data[0:len(section_data)-1]
                result += f"[Directory Name: {contents} ]"
            
            case Params.PARAM_FILENAME:
                contents = section_data[0:len(section_data)-1]
                result += f"[File Name: {contents} ]"
                
            case Params.PARAM_CODE: # Possibly response code
                contents = section_data
                if contents != b'\x00\x00\x00\x00':
                    result += f"[CODE? (Message Failure) {contents} ]"
                result += f"[CODE? (Message Success) {contents} ]"
            
            case Params.PARAM_RESPONSETASK:
                contents = section_data[0:len(section_data)-1]
                result += f"[LP TASK Name: {contents} ]"
            
            case _:
                contents = section_data
                result += f"[Unknown Data(default)? ({param}) ({contents}) ]"
            
        
    
    #result += "MAGIC_END"        
    return result

def main():
    box = create_secretbox("hildegaard+3.0.4.8+1615896246")
    #box = create_secretbox("tallulah+1.1.2.9+1615896210")
    with open(".\\decryption\\pcapreader\\data.txt",'r') as file:
        isLP = False
        for line in file:
            hex_clean = decode(box,line)
            
            point = ""
            if isLP :
                point = "LP=>Vic"
            else:
                point = "Vic=>LP"
                
            isLP = not isLP
            print(point, toText(hex_clean))
            if not isLP:
                print()

if __name__ == "__main__":
    main()
