from base64 import b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

def decryptAESkey(RSAprivateKey, encryptedAESkey):
    cipher = PKCS1_OAEP.new(RSAprivateKey)
    key = cipher.decrypt(encryptedAESkey)
    
    return key

def main():
    with open("./data/cipher_text.txt", "r") as f:
        nonce = b64decode(f.readline()[:-1]) # to remove "\n"
        cipherText = b64decode(f.readline())
        
    with open("./keys/AES_key.bin", "rb") as f:
        encryptedAESkey = f.read()

    RSAprivateKey = RSA.import_key(open("./keys/rsa_pri.pem").read())
    AESkey = decryptAESkey(RSAprivateKey, encryptedAESkey)
    
    cipherAES = AES.new(AESkey, AES.MODE_CTR, nonce=nonce)
    plainText = cipherAES.decrypt(cipherText)
    
    with open("./data/decrypted_plain_text.txt", "wb") as f:
        f.write(plainText)

if __name__ == '__main__':
    main()