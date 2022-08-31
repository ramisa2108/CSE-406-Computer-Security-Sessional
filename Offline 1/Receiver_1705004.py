import socket
import json
from Hybrid_1705004 import Hybrid
from BitVector import *


def receive_all(s, buffer_size):
	full_message = []
	while True:
		segment = s.recv(buffer_size)
		full_message += [segment.decode()]

		if len(segment) < buffer_size:
			break
	return "".join(full_message)


def main():
	s = socket.socket()
	port = 11111
	s.connect(('127.0.0.1', port))

	received = json.loads(receive_all(s, 4096))

	cipher_text, encrypted_key, rsa_public_key, send_type, file_name = received.values()
	rsa_private_key = None

	while rsa_private_key is None:
		try:
			with open("Dont Open This/prk.txt", "r") as r:
				rsa_private_key = json.loads(r.read())
		except FileNotFoundError:
			pass

	print('Private key read:', rsa_private_key)

	hybrid = Hybrid()

	print("Decrypting message...")
	deciphered = hybrid.decrypt(cipher_text, encrypted_key, rsa_public_key, rsa_private_key)
	file = open('Dont Open This/' + file_name, 'wb')
	BitVector(textstring=deciphered).write_to_file(file)

	if send_type == '1':
		print("Deciphered received message: ", deciphered)

	print('Data saved to', file_name)

	s.close()


if __name__ == '__main__':
	main()
