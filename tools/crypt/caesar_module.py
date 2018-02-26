# _*_ coding:UTF-8 _*_

from pycipher import Caesar

# 加密 向后移
def caesar_decode(string, key):
    plaintext = Caesar(int(key)).decipher(string, keep_punct=True)
    return plaintext

# 解密 向前移
def caesar_encode(string, key):
    plaintext = Caesar(int(key)).encipher(string, keep_punct=True)
    return plaintext

# 爆破
def caesar_brute(string):
    for i in range(26):
        a = caesar_encode(string, i)
        print(a)


if __name__=='__main__':
    cipher = 'e6Z9i~]8R~U~QHE{RnY{QXg~QnQ{^XVlRXlp^XI5Q6Q6SKY8jUAA'
    caesar_brute(cipher)
