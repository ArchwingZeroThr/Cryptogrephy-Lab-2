from Crypto.Cipher import AES
import base64


# 加密
def encrypt(sSrc, sKey):
    if sKey is None:
        print("Key为空null")
        return None
    # 判断Key是否为32位
    if len(sKey) != 32:
        print("Key长度不是32位")
        return None
    raw = sKey.encode('utf-8')

    # 分为前16字节和后16字节的key
    key1 = raw[:16]
    key2 = raw[16:]

    # 第一次加密
    cipher1 = AES.new(key1, AES.MODE_ECB)

    # PKCS5Padding填充
    pad = 16 - len(sSrc) % 16
    sSrc = sSrc + chr(pad) * pad

    encrypted1 = cipher1.encrypt(sSrc.encode('utf-8'))

    # 第二次加密
    cipher2 = AES.new(key2, AES.MODE_ECB)
    encrypted2 = cipher2.encrypt(encrypted1)

    return base64.b64encode(encrypted2).decode('utf-8')  # 使用BASE64做转码


# 解密
def decrypt(sSrc, sKey):
    try:
        if sKey is None:
            print("Key为空null")
            return None
        if len(sKey) != 32:
            print("Key长度不是32位")
            return None
        raw = sKey.encode('utf-8')

        # 分为前16字节和后16字节的key
        key1 = raw[:16]
        key2 = raw[16:]

        # BASE64解码
        encrypted2 = base64.b64decode(sSrc)

        # 第一次解密
        cipher2 = AES.new(key2, AES.MODE_ECB)
        decrypted1 = cipher2.decrypt(encrypted2)

        # 第二次解密
        cipher1 = AES.new(key1, AES.MODE_ECB)
        decrypted2 = cipher1.decrypt(decrypted1)

        # 去除PKCS5Padding填充
        pad = decrypted2[-1]
        decrypted2 = decrypted2[:-pad]

        return decrypted2.decode('utf-8')
    except Exception as e:
        print(str(e))
        return None


if __name__ == '__main__':
    # 需要32位的key
    cKey = "jkl;POIU1234++==jkl;POIU1234++=="
    # 需要加密的字串
    # cSrc = "www.gowhere.so"
    cSrc="ssss"
    print("原始字符串:", cSrc)

    # 加密
    enString = encrypt(cSrc, cKey)
    print("加密后的字串是：", enString)

    # 解密
    deString = decrypt(enString, cKey)
    print("解密后的字串是：", deString)
