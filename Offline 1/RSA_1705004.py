import time
from BitVector import *
import random


def find_co_prime(x):
	y = 2
	bv = BitVector(intVal=x)
	while True:
		if bv.gcd(BitVector(intVal=y)).intValue() == 1:
			return y
		else:
			y = y + 1


class RSA:
	def __init__(self, key_length, generate_key=True):
		self.key_length = key_length
		self.private_key = None
		self.public_key = None
		if generate_key:
			self.key_pair_generation()

	def set_keys(self, public_key, private_key):
		self.public_key = public_key
		self.private_key = private_key

	def generate_prime(self):
		k = self.key_length // 2
		smallest_num = (1 << (k - 1))
		largest_num = (1 << k) - 1

		while True:
			num = random.randint(smallest_num, largest_num)
			bv = BitVector(intVal=num)
			if bv.test_for_primality():
				return num

	def key_pair_generation(self):

		p = self.generate_prime()
		q = self.generate_prime()
		while p == q:
			q = self.generate_prime()

		n = p * q
		phi_n = (p - 1) * (q - 1)

		e = find_co_prime(phi_n)
		d = BitVector(intVal=e).multiplicative_inverse(BitVector(intVal=phi_n)).intValue()

		self.private_key = {"d": d, "n": n}
		self.public_key = {"e": e, "n": n}

	def encrypt(self, plain_text):

		cipher_text = []
		for p in plain_text:
			encrypted = pow(ord(p), self.public_key["e"], self.public_key["n"])
			cipher_text += [encrypted]
		return cipher_text

	def decrypt(self, cipher_text):
		decrypted_text = ""
		for c in cipher_text:
			decrypted = pow(c, self.private_key["d"], self.private_key["n"])
			decrypted_text += chr(decrypted)
		return decrypted_text


def report_time(plain_text):

	print('\nTime Related Performance:\n')
	print('---------------------------------------------------------------------------')
	print('{:<4}\t\t{:<10}\t\t{:<10}\t\t{:<10}'.format('K', 'Key-Generation (s)', 'Encryption (s)', 'Decryption (s)'))
	print('---------------------------------------------------------------------------')

	for k in [16, 32, 64, 128, 256, 512, 1024, 2048, 4096]:

		t1 = time.time()
		rsa = RSA(k)
		t2 = time.time()

		cipher_text = rsa.encrypt(plain_text)
		t3 = time.time()

		decrypted = rsa.decrypt(cipher_text)
		t4 = time.time()

		if decrypted != plain_text:
			print('plain texts don\'t match for k =', k)
		else:
			print('{:<4}\t\t{:<15.10f}\t\t\t{:<15.10f}\t\t{:<15.10f}'.format(k, t2 - t1, t3 - t2, t4 - t3))
			print('---------------------------------------------------------------------------')


def main():

	k = int(input('Enter key length: '))
	plain_text = input('Enter Plain Text: ')

	rsa = RSA(k)
	print('Generated Keys:')
	print("Public:", rsa.public_key, "Private:", rsa.private_key)
	print()

	print('Plain Text:')
	print(plain_text)
	print()

	cipher = rsa.encrypt(plain_text)
	print('Cipher Text:')
	print(cipher)
	print()

	decrypted = rsa.decrypt(cipher)
	print('Decrypted Text:')
	print(decrypted)
	print()

	if plain_text != decrypted:
		print('TEXTS DON"T MATCH!!')

	report_time(plain_text)


if __name__ == '__main__':
	main()


