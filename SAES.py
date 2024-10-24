import tkinter as tk
from tkinter import messagebox
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

# S-AES 加解密相关的函数
# S盒
s = [[9, 4, 10, 11],
     [13, 1, 8, 5],
     [6, 2, 0, 3],
     [12, 14, 15, 7]]
# s逆盒
s2 = [[10, 5, 9, 11],
      [1, 7, 8, 15],
      [6, 0, 2, 3],
      [12, 4, 13, 14]]
# 轮密钥
w2 = ""
w3 = ""
w4 = ""
w5 = ""
# RCON
RCON1 = "10000000"
RCON2 = "00110000"

# 二进制异或
def xor_binary(bin1, bin2):
    max_len = max(len(bin1), len(bin2))
    bin1 = bin1.zfill(max_len)
    bin2 = bin2.zfill(max_len)
    result = [str(int(b1) ^ int(b2)) for b1, b2 in zip(bin1, bin2)]
    return ''.join(result)

# 加密字节替换
def SubBytes(input, Spd):
    S1 = input[0:len(input)//4]
    S2 = input[len(input)//4:len(input)//2]
    S3 = input[len(input)//2:len(input)*3//4]
    S4 = input[len(input)*3//4:len(input)]
    parts = [S1, S2, S3, S4]
    output = []
    for S in parts:
        S11 = S[:2]
        S12 = S[2:]
        if Spd == 1:
            result = s[int(S11, 2)][int(S12, 2)]
        else:
            result = s2[int(S11, 2)][int(S12, 2)]
        output.append(format(result, '04b'))
    return ''.join(output)

# 行位移
def Rowdisplacement(input):
    S1 = input[0:len(input)//4]
    S2 = input[len(input)//4:len(input)//2]
    S3 = input[len(input)//2:len(input)*3//4]
    S4 = input[len(input)*3//4:len(input)]
    parts = [S1, S4, S3, S2]
    return ''.join(parts)

# 乘法GF（2^4）
def galois_mult(a, b):
    b = int(b, 2)
    p = 0
    while a and b:
        if b & 1:
            p ^= a
        if a & 0x8:
            a = (a << 1) ^ 0x13
        else:
            a <<= 1
        b >>= 1
    return format(p & 0xF, '04b')

# 列混淆
def Columnconfusion(input):
    S1 = input[0:len(input)//4]
    S2 = input[len(input)//4:len(input)//2]
    S3 = input[len(input)//2:len(input)*3//4]
    S4 = input[len(input)*3//4:]
    M1 = xor_binary(S1, galois_mult(4, S2))
    M2 = xor_binary(S2, galois_mult(4, S1))
    M3 = xor_binary(S3, galois_mult(4, S4))
    M4 = xor_binary(S4, galois_mult(4, S3))
    return ''.join([M1, M2, M3, M4])

# 逆列混淆
def inverse_column_confusion(input):
    S1 = input[0:len(input)//4]
    S2 = input[len(input)//4:len(input)//2]
    S3 = input[len(input)//2:len(input)*3//4]
    S4 = input[len(input)*3//4:]
    M1 = xor_binary(galois_mult(9, S1), galois_mult(2, S2))
    M2 = xor_binary(galois_mult(9, S2), galois_mult(2, S1))
    M3 = xor_binary(galois_mult(9, S3), galois_mult(2, S4))
    M4 = xor_binary(galois_mult(9, S4), galois_mult(2, S3))
    return ''.join([M1, M2, M3, M4])

# 8bit字节向左偏移4bit函数
def presre(binary_str):
    return binary_str[4:] + binary_str[:4]

# 获取w2与w3
def KeyStretching(key):
    w0 = key[:len(key)//2]
    w1 = key[len(key)//2:]
    global w2, w3, w4, w5
    key_temp1 = SubBytes(key, 1)
    temp2 = key_temp1[len(key_temp1)//2:]
    po1 = presre(temp2)
    w2 = xor_binary(xor_binary(RCON1, w0), po1)
    w3 = xor_binary(w2, w1)
    w3y = presre(w3)
    po = w2 + w3y
    key_temp2 = SubBytes(po, 1)
    temp3 = key_temp2[len(key_temp2)//2:]
    w4 = xor_binary(xor_binary(RCON2, w2), temp3)
    w5 = xor_binary(w4, w3)

# S-AES 加密函数
def s_aes_encrypt(plaintext_16bit, key_16bit):
    zero = xor_binary(plaintext_16bit, key_16bit)
    KeyStretching(key_16bit)
    key2 = w2 + w3
    key3 = w4 + w5
    def round_function(cip, key, pd):
        state = SubBytes(cip, 1)
        state = Rowdisplacement(state)
        if pd == 1:
            state = Columnconfusion(state)
        return xor_binary(state, key)
    first_round_output = round_function(zero, key2, 1)
    final_output = round_function(first_round_output, key3, 2)
    return final_output

# S-AES 解密函数
def s_aes_decrypt(ciphertext_16bit, key_16bit):
    KeyStretching(key_16bit)
    key2 = w2 + w3
    key3 = w4 + w5
    zero = xor_binary(ciphertext_16bit, key3)
    def round_function(cip, key, pd):
        state = Rowdisplacement(cip)
        state = SubBytes(state, 2)
        state = xor_binary(state, key)
        if pd == 1:
            state = inverse_column_confusion(state)
        return state
    first_round_output = round_function(zero, key2, 1)
    final_output = round_function(first_round_output, key_16bit, 2)
    return final_output

# AES 加解密相关的函数
def aes_encrypt(sSrc, sKey):
    if sKey is None:
        print("Key为空null")
        return None
    if len(sKey) != 16:
        print("Key长度不是16位")
        return None
    raw = sKey.encode('utf-8')
    cipher = AES.new(raw, AES.MODE_ECB)

    # PKCS5Padding
    pad = 16 - len(sSrc) % 16
    sSrc = sSrc + chr(pad) * pad

    encrypted = cipher.encrypt(sSrc.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')  # 使用BASE64做转码

def aes_decrypt(sSrc, sKey):
    try:
        if sKey is None:
            print("Key为空null")
            return None
        if len(sKey) != 16:
            print("Key长度不是16位")
            return None
        raw = sKey.encode('utf-8')
        cipher = AES.new(raw, AES.MODE_ECB)

        encrypted1 = base64.b64decode(sSrc)
        original = cipher.decrypt(encrypted1)

        # 去除填充的PKCS5Padding
        pad = original[-1]
        original = original[:-pad]

        return original.decode('utf-8')
    except Exception as e:
        print(str(e))
        return None

def cbc_encrypt(plaintext,key):
    raw = key.encode('utf-8')

    # 生成随机IV
    iv = os.urandom(16)
    cipher = AES.new(raw, AES.MODE_CBC, iv)

    # 使用pad函数进行填充
    padded_text = pad(plaintext.encode('utf-8'), AES.block_size)

    encrypted = cipher.encrypt(padded_text)
    return base64.b64encode(iv + encrypted).decode('utf-8')
# GUI代码
def create_gui():
    def on_s_aes_encrypt():
        plaintext = entry_plaintext.get()
        key = entry_key.get()
        if len(plaintext) != 16 or len(key) != 16:
            messagebox.showerror("错误", "明文和密钥必须是16位二进制字符串")
            return
        encrypted = s_aes_encrypt(plaintext, key)
        messagebox.showinfo("S-AES 加密结果", f"加密后的数据: {encrypted}")

    def on_s_aes_decrypt():
        ciphertext = entry_ciphertext.get()
        key = entry_key.get()
        if len(ciphertext) != 16 or len(key) != 16:
            messagebox.showerror("错误", "密文和密钥必须是16位二进制字符串")
            return
        decrypted = s_aes_decrypt(ciphertext, key)
        messagebox.showinfo("S-AES 解密结果", f"解密后的数据: {decrypted}")

    def on_aes_encrypt():
        plaintext = entry_plaintext.get()
        key = entry_key.get()
        encrypted = aes_encrypt(plaintext, key)
        messagebox.showinfo("AES 加密结果", f"加密后的数据: {encrypted}")

    def on_aes_decrypt():
        ciphertext = entry_ciphertext.get()
        key = entry_key.get()
        decrypted = aes_decrypt(ciphertext, key)
        messagebox.showinfo("AES 解密结果", f"解密后的数据: {decrypted}")

    window = tk.Tk()
    window.title("加解密工具")

    tk.Label(window, text="明文/密文:").grid(row=0, column=0)
    entry_plaintext = tk.Entry(window)
    entry_plaintext.grid(row=0, column=1)

    tk.Label(window, text="密钥:").grid(row=1, column=0)
    entry_key = tk.Entry(window)
    entry_key.grid(row=1, column=1)

    tk.Button(window, text="S-AES 加密", command=on_s_aes_encrypt).grid(row=2, column=0)
    tk.Button(window, text="S-AES 解密", command=on_s_aes_decrypt).grid(row=2, column=1)
    tk.Button(window, text="AES 加密", command=on_aes_encrypt).grid(row=3, column=0)
    tk.Button(window, text="AES 解密", command=on_aes_decrypt).grid(row=3, column=1)

    window.mainloop()

if __name__ == '__main__':
    create_gui()
