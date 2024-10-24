from Crypto.Cipher import AES
import base64


# AES加密
def encrypt(sSrc, sKey):
    if sKey is None:
        print("Key为空null")
        return None
    # 判断Key是否为48位
    if len(sKey) != 48:
        print("Key长度不是48位")
        return None
    rawKey = sKey.encode('utf-8')

    # 分割成三个16字节的子密钥
    key1 = rawKey[:16]
    key2 = rawKey[16:32]
    key3 = rawKey[32:48]

    # 使用AES算法进行三次加密
    encrypted = sSrc.encode('utf-8')

    cipher = AES.new(key1, AES.MODE_ECB)
    pad = 16 - len(encrypted) % 16
    encrypted += bytes([pad] * pad)

    # 第一次加密
    encrypted = cipher.encrypt(encrypted)

    # 第二次加密
    cipher = AES.new(key2, AES.MODE_ECB)
    encrypted = cipher.encrypt(encrypted)

    # 第三次加密
    cipher = AES.new(key3, AES.MODE_ECB)
    encrypted = cipher.encrypt(encrypted)

    return base64.b64encode(encrypted).decode('utf-8')


# AES解密
def decrypt(sSrc, sKey):
    if sKey is None:
        print("Key为空null")
        return None
    if len(sKey) != 48:
        print("Key长度不是48位")
        return None
    rawKey = sKey.encode('utf-8')

    # 分割成三个16字节的子密钥
    key1 = rawKey[:16]
    key2 = rawKey[16:32]
    key3 = rawKey[32:48]

    # 使用AES算法进行三次解密
    decrypted = base64.b64decode(sSrc)

    cipher = AES.new(key3, AES.MODE_ECB)

    # 第三次解密
    decrypted = cipher.decrypt(decrypted)

    # 第二次解密
    cipher = AES.new(key2, AES.MODE_ECB)
    decrypted = cipher.decrypt(decrypted)

    # 第一次解密
    cipher = AES.new(key1, AES.MODE_ECB)
    decrypted = cipher.decrypt(decrypted)

    # 去除PKCS5Padding填充
    pad = decrypted[-1]
    decrypted = decrypted[:-pad]

    return decrypted.decode('utf-8')


if __name__ == '__main__':
    # 需要48字节的key
    cKey = "jkl;POIU1234++==jkl;POIU1234++==jkl;POIU1234++=="
    # 需要加密的字串
    cSrc = "www.gowhere.so"
    print("原始字符串:", cSrc)

    a=decrypt(cSrc,cKey)
    print(a)
    # 加密
    enString = encrypt(cSrc, cKey)
    print("加密后的字串是：", enString)

    # 解密
    deString = decrypt(enString, cKey)
    print("解密后的字串是：", deString)
