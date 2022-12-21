# RSA-AES_CTR-hybird--encryption

data資料夾內含有data.txt => 原文的文字檔案；cipher_text.txt => 原文經過AES加密過後得到的密文，第一行為nonce、第二行為密文，經過base64編碼再由utf-8解碼；
decrypted_plain_text.txt => AES解密密文過後得到的原文，應與data.txt完全相同

keys資料夾內含有rsa_pri.pem跟rsa_pub.pem，分別為RSA 2048的私鑰和公鑰；AES_key.bin為AES 256的金鑰經由RSA加密過的bin檔

先執行encrypy.py讀取data.txt的原文、生成RSA 2048 public跟private key、AES 256 key，並且用AES加密原文，最後用RSA public key加密AES key
再執行decrypt.py讀取加密的AES key、RSA private key、密文，並且將AES key用RSA private key解密，最後再將密文使用AES key還原成原文
