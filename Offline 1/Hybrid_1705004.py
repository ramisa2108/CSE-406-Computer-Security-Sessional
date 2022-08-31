from RSA_1705004 import RSA
from AES_1705004 import AES


class Hybrid:
	def __init__(self):
		self.aes = None
		self.rsa = None

	def set_rsa(self, key_length, public_key=None, private_key=None):
		if public_key is None:
			self.rsa = RSA(key_length)
		else:
			self.rsa = RSA(key_length, False)
			self.rsa.set_keys(public_key, private_key)

	def set_aes(self, key):
		self.aes = AES(key)

	def encrypt(self, plain_text, aes_key):
		cipher_text = self.aes.encrypt(plain_text)
		encrypted_key = self.rsa.encrypt(aes_key)
		return cipher_text, encrypted_key

	def decrypt(self, cipher_text, encrypted_key, rsa_public_key, rsa_private_key):
		self.set_rsa(0, rsa_public_key, rsa_private_key)
		aes_key = self.rsa.decrypt(encrypted_key)
		print('Deciphered AES key:', aes_key)
		self.set_aes(aes_key)
		return self.aes.decrypt(cipher_text)
