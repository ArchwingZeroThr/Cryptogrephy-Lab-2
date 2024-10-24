from Crypto.Cipher import AES
import base64

# AES加密函数
def encrypt(plaintext, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    pad = 16 - len(plaintext) % 16
    plaintext += chr(pad) * pad
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

# AES解密函数
def decrypt(ciphertext, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    ciphertext = base64.b64decode(ciphertext)
    decrypted = cipher.decrypt(ciphertext)
    pad = decrypted[-1]
    return decrypted[:-pad].decode('utf-8')

def attack(plaintext_input,ciphertext_input):
    plaintext = plaintext_input  # 要加密的明文
    ciphertext = ciphertext_input  # 要解密的密文

    # 穷举16位密钥k1
    for k1 in range(0, 65536):
        k1Str = bin(k1)[2:].zfill(16)

        try:
            # 使用k1加密明文得到中间密文
            ciph_mid = encrypt(plaintext, k1Str)

            # 穷举16位密钥k2
            for k2 in range(0, 65536):
                k2Str = bin(k2)[2:].zfill(16)

                try:
                    # 使用k2解密密文
                    dec_mid = decrypt(ciphertext, k2Str)

                    # 判断是否匹配
                    if dec_mid == ciph_mid:
                        key = k1Str + k2Str  # 组成K（k1+k2）
                        print("Found key:", key)
                        return key # 找到满足条件的k1和k2，结束穷举
                except Exception as e:
                    # 解密过程中出现异常，继续穷举下一个k2
                    continue
        except Exception as e:
            # 加密过程中出现异常，继续穷举下一个k1
            continue

    print("No matching key found.")

if __name__ == '__main__':
    min="2"
    mi="ueyTgg+k5gKJ3K9cNbqCAQ=="
    out=attack(min,mi)
    print(out)