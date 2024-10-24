# S-AES算法实现

## 一·AES算法简介

AES（Advanced Encryption Standard）是一种广泛使用的对称密钥加密标准，由美国国家标准与技术研究院（NIST）于2001年发布，用以取代旧的数据加密标准（DES）。AES加密算法以其高安全性和快速的加解密速度而闻名，在软件和硬件上都能高效运行，且实现相对简单，需要的存储空间较少。

### AES算法加密步骤

#### （一）密钥扩展（Key Expansion）：将原始密钥扩展成多个轮密钥，每个轮密钥用于加密过程中的一轮。

- 初始密钥被分成4个字（每个字4个字节）的序列。
- 通过一系列的操作，包括字循环（RotWord），字节替换（SubWord），以及轮常量（Rcon）的应用，生成一系列轮密钥。
- AES-128需要10轮，因此需要生成10个轮密钥；AES-192需要12轮，生成12个轮密钥；AES-256需要14轮，生成14个轮密钥。

#### （二）初始轮（AddRoundKey）：将明文与初始密钥进行按位异或操作。

#### （三）多轮迭代：每轮迭代包括以下四个步骤：

​	①SubBytes：通过非线性的替换函数，用查找表的方式把每个字节替换成对应的字节。
​	②ShiftRows：将矩阵中的每个横列进行循环式移位。
​	③MixColumns：使用线性转换来混合每列的四个字节。
​	④AddRoundKey：将每个状态中的字节与该轮的轮密钥做异或操作。

#### （四）最后一轮：不包括MixColumns操作，仅进行SubBytes、ShiftRows和AddRoundKey操作。

PS：*解密过程与加密过程类似，但使用的是逆操作，包括逆SubBytes、逆ShiftRows、逆MixColumns和逆AddRoundKey操作。*

## 二·S-AES算法实现

### （一）密钥扩展

- 该代码基于一个简化的密钥结构和扩展方式。它将输入密钥分为两个部分（w0 和 w1），并在扩展过程中只生成四个轮密钥（w2、w3、w4 和 w5），而不是像AES那样生成多个轮密钥。

```python
#密钥扩展函数
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
```

- 其中使用到了SubBytes这个函数：

  对状态矩阵中的每个字节进行非线性替换。

```python
#字节替换
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

```

- 使用的S盒与S逆盒如下：

```python
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
```

### （二）S-AES加解密

- 代码如下：

```python
#S-AES 加密函数
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
```

- 具象化的UI界面

  <img src="image\image-20241024150229154.png" alt="image-20241024150229154" style="zoom: 50%;" />

输入明文与密钥后，点击S-AES加密（16bits密钥）即可求得密文

***PS:明文与密文都必须为16bits的二进制，解密同理***

## 二·交叉测试

- 其他小组的加密结果：

<img src="image\image-20241024161823296.png" alt="image-20241024161823296" style="zoom:50%;" />



- 本小组的解密结果

<img src="image\image-20241024161926587.png" alt="image-20241024161926587" style="zoom:50%;" />

解出的明文可以对应上，故交叉验证成功

## 三·扩展功能

考虑到向实用性扩展，加密算法的数据输入可以是ASII编码字符串(分组为2 Bytes)，对应地输出也可以是ACII字符串(很可能是乱码)

- 具体代码实现：

```python
#加密函数
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
#解密函数
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
```

***值得一提的是：使用BASE64编码和解码，是由于BASE64编码的数据只包含ASCII字符，因此在不同系统和网络之间传输时不会出现编码不一致导致的乱码问题。***

- UI界面体现

  ①加密

<img src="C:\Users\86151\AppData\Roaming\Typora\typora-user-images\image-20241024152121344.png" alt="image-20241024152121344" style="zoom:50%;" />

***输入明文与密钥后，点击ASCII码加密（16bits密钥）即可求得密文***

​	②解密

<img src="image\image-20241024152300535.png" alt="image-20241024152300535" style="zoom:50%;" />

***输入密文与密钥后，点击ASCII码解密（16bits密钥）即可求得明文***

## 四·多重加密

### （一） 双重加解密

​					将S-AES算法通过双重加密进行扩展，分组长度仍然是16 bits，但密钥长度为32 bits。

- 具体代码实现：

```python
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

```

- UI界面体现

  加密：

  <img src="image\image-20241024152811846.png" alt="image-20241024152811846" style="zoom:50%;" />

  ***输入明文与密钥后，点击双重加密（32bits密钥）即可求得密文***

  解密：

  <img src="image\image-20241024152858452.png" alt="image-20241024152858452" style="zoom:50%;" />

***输入密文与密钥后，点击双重解密（32bits密钥）即可求得明文***

### （二）三重加解密

​			将S-AES算法通过三重加密进行扩展，使用48bits(K1+K2+K3)的模式进行三重加解密

- 具体代码如下

  ```python
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
  
  ```

- UI界面体现

  加密：

  <img src="image\image-20241024153531079.png" alt="image-20241024153531079" style="zoom:50%;" />

  ***输入明文与密钥后，点击三重加密（48bits密钥）即可求得密文***

  解密：

  <img src="image\image-20241024153622279.png" alt="image-20241024153622279" style="zoom:50%;" />

***输入密文与密钥后，点击三重解密（48bits密钥）即可求得明文***

### （三）中间相遇攻击求密钥

- 具体代码实现：

```python
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
```

- UI界面体现

  <img src="image\image-20241024161335011.png" alt="image-20241024161335011" style="zoom:50%;" />

  点击“进入求密钥模式”，输入明文与密文。

  <img src="image\image-20241024161444138.png" alt="image-20241024161444138" style="zoom:50%;" />

## 五·工作模式

基于S-AES算法，使用密码分组链(CBC)模式对较长的明文消息进行加密。

- 具体代码如下：

```python
def cbc_encrypt(plaintext,key):
    raw = key.encode('utf-8')

    # 生成随机IV
    iv = os.urandom(16)
    cipher = AES.new(raw, AES.MODE_CBC, iv)

    # 使用pad函数进行填充
    padded_text = pad(plaintext.encode('utf-8'), AES.block_size)

    encrypted = cipher.encrypt(padded_text)
    return base64.b64encode(iv + encrypted).decode('utf-8')
```

- AES算法的ECB工作模式与CBC工作模式有以下不同之处：

| 特性                 | ECB（电子密码本模式）                                  | CBC（密码块链接模式）                                      |
| -------------------- | ------------------------------------------------------ | ---------------------------------------------------------- |
| **加密方式**         | 每个明文块独立加密，使用相同的密钥。                   | 每个明文块在加密前与前一个密文块进行异或操作。             |
| **初始化向量**       | 不需要初始化向量（IV）。                               | 需要一个随机的初始化向量（IV）。                           |
| **并行处理**         | 可以并行处理多个明文块。                               | 不能并行处理，因为每个块依赖于前一个块的结果。             |
| **相同明文块的处理** | 相同的明文块会产生相同的密文块。                       | 相同的明文块会产生不同的密文块（取决于IV和前一个密文块）。 |
| **安全性**           | 安全性较低，容易受到模式分析攻击。                     | 安全性较高，能有效抵抗模式分析攻击。                       |
| **错误传播**         | 仅影响当前块，其他块不受影响。                         | 如果一个密文块被篡改，后续的所有块都会受到影响。           |
| **适用场景**         | 不推荐用于敏感数据的加密，适合对安全性要求不高的场景。 | 适用于大多数需要加密敏感数据的场景。                       |

- UI界面体现

  <img src="C:\Users\86151\AppData\Roaming\Typora\typora-user-images\image-20241024155054672.png" alt="image-20241024155054672" style="zoom:50%;" />

  点击“进入CBC模式”按钮后，进入CBC模式：

  <img src="C:\Users\86151\AppData\Roaming\Typora\typora-user-images\image-20241024155145308.png" alt="image-20241024155145308" style="zoom:50%;" />

  ***输入明文与密钥后，点击CBC加密（16bits密钥）即可求得密文***

  

  ## 六·总结

  学习AES时，重点在于理解其安全性、不同的工作模式以及如何在实际应用中使用。

  学习S-AES时，重点在于掌握AES的基本原理，如块加密、密钥扩展、轮函数等。

  总结来说，S-AES是学习AES的一个良好起点，它通过简化AES的某些方面，使得初学者能够更容易地理解加密算法的基本概念和工作原理。一旦掌握了S-AES，就可以更深入地学习AES的高级特性和应用。

  

  ## 七·鸣谢

  - 课程名称：信息安全导论

  - 教学班级：992987-002

  - 任课教师：向宏

  - 单位：重庆大学大数据与软件学院

  - 小组：猫的摇篮

  - 成员：刘子昂、刘鲲遥、冉紫阳

  - 若有任何疑问或建议，请联系开发团队：1318147137@qq.com

