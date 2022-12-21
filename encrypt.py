from base64 import b64encode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def generateRSA(RSAkey):
    with open("./keys/rsa_pri.pem", "wb") as f:
        f.write(RSAkey.export_key())
        
    with open("./keys/rsa_pub.pem", "wb") as f:
        f.write(RSAkey.public_key().export_key())
        
    return RSAkey.public_key().export_key()

def encryptAES(data, key):
    cipher = AES.new(key, AES.MODE_CTR)
    ciphertext_bytes = cipher.encrypt(data)
    ciphertext = b64encode(ciphertext_bytes).decode('utf-8')
    nonce = b64encode(cipher.nonce).decode('utf-8')
    
    return ciphertext, nonce

def encryptAESkey(AESkey, RSApublicKey):
    key = RSA.import_key(RSApublicKey) # transform key bytes to RSA key object
    cipher = PKCS1_OAEP.new(key)
    encryptedAESkey = cipher.encrypt(AESkey)
    return encryptedAESkey
     
def main():
    with open('./data/data.txt', 'rb') as f:
        data = f.read()
    
    RSAkey = RSA.generate(2048)
    RSApublicKey = generateRSA(RSAkey) #RSA keys generation
    
    AESkey = get_random_bytes(32)
    
    ciphertext, nonce = encryptAES(data, AESkey) #AES encyption on data.txt
    with open("./data/cipher_text.txt", "w") as f:
        f.write(nonce)
        f.write("\n")
        f.write(ciphertext)
        
    with open("./keys/AES_key.bin", "wb") as f:
        f.write(encryptAESkey(AESkey, RSApublicKey))
    
if __name__ == '__main__':
    main()