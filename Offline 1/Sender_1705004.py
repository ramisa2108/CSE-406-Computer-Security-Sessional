import socket
from Hybrid_1705004 import Hybrid
import json
from BitVector import *


def main():

	aes_key = input('Enter AES key: ')
	rsa_key_length = int(input('Enter key length for RSA: '))

	hybrid = Hybrid()
	hybrid.set_rsa(rsa_key_length)
	hybrid.set_aes(aes_key)

	send_type = input('Choose Option Number:\n1. Send Message\t2. Send File\n')
	if send_type == '1':
		plain_text = input('Enter message to send: ')
		file_name = 'Decrypted Plain Text'
	else:
		file_name = input('Enter file name: ')
		with open('Sender Files/'+file_name, 'rb') as file:
			bytes_data = file.read()
			plain_text = BitVector(rawbytes=bytes_data).get_text_from_bitvector()

	print('Encrypting message...')

	cipher_text, encrypted_key = hybrid.encrypt(plain_text, aes_key)

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	port = 11111
	s.bind(('', port))
	s.listen(5)

	print('Connection opened...')

	c, address = s.accept()
	print('Connected to address', address)

	to_send = {
		"cipher_text": cipher_text, "encrypted_key": encrypted_key,
		"rsa_public_key": hybrid.rsa.public_key, "message_type": send_type,
		"file_name": file_name
	}

	with open("Dont Open This/prk.txt", "w") as w:
		w.write(json.dumps(hybrid.rsa.private_key))

	c.sendall(json.dumps(to_send).encode())
	print('Sent message.')
	print('Private key written: ', hybrid.rsa.private_key)
	c.close()

	read_back_data = None
	while read_back_data is None:
		try:
			with open("Dont Open This/" + file_name, "rb") as file:
				bytes_data = file.read()
				read_back_data = BitVector(rawbytes=bytes_data).get_text_from_bitvector()
		except:
			pass

	if read_back_data != plain_text:
		print("Sent and received data don't match")
	else:
		print("Sent and received data match")


if __name__ == '__main__':
	main()

