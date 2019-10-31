import base64
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

def add_to_16_ECB(value):
    while len(value) % 16 != 0:
        value += '\0'
    return str.encode(value)  # 返回bytes

class aes_ecb():
    # str不是16的倍数那就补足为16的倍数
    def __init__(self,key):
        self.key=key
        self.mode=AES.MODE_ECB
    #加密方法
    def encrypt(self,text):
        key = self.key
        # 待加密文本
        #text = 'abc123def456'
        # 初始化加密器
        aes = AES.new(add_to_16_ECB(key), self.mode)
        #先进行aes加密
        encrypt_aes = aes.encrypt(add_to_16_ECB(text))
        #用base64转成字符串形式
        encrypted_text = str(base64.encodebytes(encrypt_aes), encoding='utf-8')  # 执行加密并转码返回bytes
        print("ECB加密的密文是: "+encrypted_text)
        return encrypted_text
    #解密方法
    def decrypt(self,text):
        key = self.key
        # 密文
        #text = 'qR/TQk4INsWeXdMSbCDDdA=='
        # 初始化加密器
        aes = AES.new(add_to_16_ECB(key), self.mode)
        #优先逆向解密base64成bytes
        base64_decrypted = base64.decodebytes(text.encode(encoding='utf-8'))
        #执行解密密并转码返回str，注意decrypt接收的密文必须是bytes类型
        decrypted_text = str(aes.decrypt(base64_decrypted),encoding='utf-8').replace('\0','')
        print("ECB解密得密文是: "+decrypted_text)
        return decrypted_text

class aes_cbc():
    def __init__(self, key):
        self.key = add_to_16_ECB(key)
        self.mode = AES.MODE_CBC

    # 加密函数，如果text不是16的倍数【加密文本text必须为16的倍数！】，那就补足为16的倍数
    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.key)
        text = text.encode("utf-8")
        # 这里密钥key 长度必须为16（AES-128）、24（AES-192）、或32（AES-256）Bytes 长度.目前AES-128足够用
        length = 16
        count = len(text)
        add = length - (count % length)
        text = text + (b'\0' * add)
        self.ciphertext = cryptor.encrypt(text)
        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        res=b2a_hex(self.ciphertext).decode("ASCII")
        print("CBC加密的密文是: "+res)
        return res

    # 解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.key)
        plain_text = cryptor.decrypt(a2b_hex(text))
        res=plain_text.rstrip(b'\0').decode("utf-8")
        print("CBC解密的密文是: "+res)
        return res


if __name__ == '__main__':
    a= aes_ecb('123456')
    enc = a.encrypt('hello')
    a.decrypt(enc)
    b=aes_cbc('123456')
    c=b.encrypt('world')
    b.decrypt(c)
