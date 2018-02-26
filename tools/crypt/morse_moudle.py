# coding:utf-8 


class Morse(object):

    def __init__(self):
	
	self.morse_dict = {}
	
	f = open('morse_dict.txt','r')

	content = []

	for line in f.readlines():
	    content.append(line.strip())
	
	for i in range(0, len(content), 2):
	    self.morse_dict[content[i]] = content[i+1]
	
	#print self.morse_dict



    def morse_encode(self, plain_str):
	
	crypt_str = ''
	
	for c in plain_str:
	    crypt_str += self.morse_dict[c]
	    crypt_str += ' '
	
	return crypt_str


    def morse_decode(self, crypt_str):
	
	plain_str = ''
	crypt_array = crypt_str.split(' ')
	flip_morse_dict = {v: k for k,v in self.morse_dict.items()}

	for c in crypt_array:
	    plain_str += flip_morse_dict[c]
	
	return plain_str


if __name__ == '__main__':
    
    decrypt_str = '.... - - .--. ... ---... -..-. -..-. .-- .. -. -.. -.-- .-- .- .-. . .-.-. --. .. - .... ..- -... .-.-. .. ---'
    encrypt_str = 'https://windyware.github.io'
    encrypt_str = '-... -.- -.-. - ..-. -- .. ... -.-.'

    morse = Morse()
    
    #print morse.morse_encode(encrypt_str.upper())
    #print morse.morse_decode(decrypt_str)

    print 'key{'+morse.morse_decode(encrypt_str).lower()+'}'



