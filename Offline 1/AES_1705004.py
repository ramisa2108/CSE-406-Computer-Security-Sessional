
from AESutils_1705004 import *
from BitVector import *
import time


class AES:
	def __init__(self, key, mode=128):

		if not (mode == 128 or mode == 192 or mode == 256):
			print(mode, 'bit mode is not supported in AES. Switching to default 128 bit mode.\n')
			mode = 128

		self.mode = mode
		if self.mode == 128:
			self.rounds = 10
		elif self.mode == 192:
			self.rounds = 12
		else:
			self.rounds = 14

		self.rows = self.cols = 4
		self.key = ascii_to_hex(key)
		self.adjust_key_length()
		self.round_keys = None
		self.generate_round_keys()

	def adjust_key_length(self):
		# slice if key is too large
		self.key = self.key[:self.mode // 4]
		# pad if key is too small
		self.key = '0' * (self.mode // 4 - len(self.key)) + self.key

	def generate_round_keys(self):

		self.round_keys = []
		# n = 4, 6, 8 for mode = 128, 192, 256
		n = self.mode // 32

		# generate rounds
		total_keys = 4 * (self.rounds + 1)
		self.round_keys = [[] for _ in range(total_keys)]

		for i in range(total_keys):
			if i < n:
				segment = self.key[i * 8: (i + 1) * 8]
				self.round_keys[i] = [BitVector(hexstring=segment[j * 2:(j + 1) * 2]) for j in range(self.cols)]
			elif i % n == 0:
				self.round_keys[i] = elementwise_xor(self.round_keys[i - n], g(self.round_keys[i - 1], i // n - 1))
			elif n > 6 and i % n == 4:
				self.round_keys[i] = elementwise_xor(self.round_keys[i - n], elementwise_substitution(self.round_keys[i - 1]))
			else:
				self.round_keys[i] = elementwise_xor(self.round_keys[i - n], self.round_keys[i - 1])

	def add_round_key(self, state_matrix, round_num):

		round_key = [[self.round_keys[round_num*4+j][i] for j in range(self.cols)] for i in range(self.rows)]
		for i in range(self.cols):
			state_matrix[i] = elementwise_xor(state_matrix[i], round_key[i])
		return state_matrix

	def substitute_bytes(self, state_matrix):
		for i in range(self.rows):
			state_matrix[i] = elementwise_substitution(state_matrix[i])
		return state_matrix

	def inverse_substitute_bytes(self, state_matrix):
		for i in range(self.rows):
			state_matrix[i] = elementwise_inverse_substitution(state_matrix[i])
		return state_matrix

	def shift_rows(self, state_matrix):
		for i in range(self.rows):
			state_matrix[i] = left_shift(state_matrix[i], i)
		return state_matrix

	def inverse_shift_rows(self, state_matrix):
		for i in range(self.rows):
			state_matrix[i] = right_shift(state_matrix[i], i)
		return state_matrix

	def mix_columns(self, state_matrix):

		temp = [[] for _ in range(self.rows)]
		for i in range(self.rows):
			for j in range(self.cols):
				x = BitVector(intVal=0)
				for k in range(self.rows):
					x ^= Mixer[i][k].gf_multiply_modular(state_matrix[k][j], AES_modulus, 8)
				temp[i] += [x]

		state_matrix = temp
		return state_matrix

	def inverse_mix_columns(self, state_matrix):
		temp = [[] for _ in range(self.rows)]
		for i in range(self.rows):
			for j in range(self.cols):
				x = BitVector(intVal=0)
				for k in range(self.rows):
					x ^= InvMixer[i][k].gf_multiply_modular(state_matrix[k][j], AES_modulus, 8)
				temp[i] += [x]

		state_matrix = temp
		return state_matrix

	def encrypt_block(self, block):

		state_matrix = [[BitVector(intVal=0, size=8)] * self.cols for _ in range(self.rows)]
		for j in range(self.cols):
			segment = block[j * 8: (j + 1) * 8]
			for i in range(self.rows):
				state_matrix[i][j] = BitVector(hexstring=segment[i*2: (i+1)*2])

		state_matrix = self.add_round_key(state_matrix, 0)

		# rounds with 4 steps
		for r in range(1, self.rounds):

			state_matrix = self.substitute_bytes(state_matrix)

			state_matrix = self.shift_rows(state_matrix)

			state_matrix = self.mix_columns(state_matrix)

			state_matrix = self.add_round_key(state_matrix, r)

		# last round with 3 steps
		state_matrix = self.substitute_bytes(state_matrix)

		state_matrix = self.shift_rows(state_matrix)

		state_matrix = self.add_round_key(state_matrix, self.rounds)

		cipher_text = ""
		for i in range(self.cols):
			for j in range(self.rows):
				cipher_text += state_matrix[j][i].get_hex_string_from_bitvector()

		return cipher_text

	def encrypt(self, plain_text):

		# convert to hexadecimal
		hex_text = ascii_to_hex(plain_text)

		# add padding to make multiple of block size
		hex_text = add_padding(hex_text)

		# divide the message into blocks
		number_of_blocks = len(hex_text) * 4 // AES_block_size
		hex_block_size = AES_block_size // 4

		encrypted_message = ""
		for i in range(number_of_blocks):
			current_block = hex_text[i * hex_block_size: (i + 1) * hex_block_size]
			encrypted_message += self.encrypt_block(current_block)

		return hex_to_ascii(encrypted_message)

	def decrypt_block(self, block):

		state_matrix = [[BitVector(intVal=0, size=8)] * self.cols for _ in range(self.rows)]
		for j in range(self.cols):
			segment = block[j * 8: (j + 1) * 8]
			for i in range(self.rows):
				state_matrix[i][j] = BitVector(hexstring=segment[i * 2: (i + 1) * 2])

		self.add_round_key(state_matrix, self.rounds)

		# rounds with 4 steps
		for r in range(self.rounds-1, 0, -1):
			state_matrix = self.inverse_shift_rows(state_matrix)
			state_matrix = self.inverse_substitute_bytes(state_matrix)
			state_matrix = self.add_round_key(state_matrix, r)
			state_matrix = self.inverse_mix_columns(state_matrix)

		# last round with 3 steps
		state_matrix = self.inverse_shift_rows(state_matrix)
		state_matrix = self.inverse_substitute_bytes(state_matrix)
		state_matrix = self.add_round_key(state_matrix, 0)

		plain_text = ""
		for i in range(self.cols):
			for j in range(self.rows):
				plain_text += state_matrix[j][i].get_hex_string_from_bitvector()

		return plain_text

	def decrypt(self, cipher_text):
		# convert to hexadecimal
		hex_text = ascii_to_hex(cipher_text)

		# divide the message into blocks
		number_of_blocks = len(hex_text) * 4 // AES_block_size
		hex_block_size = AES_block_size // 4

		decrypted_message = ""
		for i in range(number_of_blocks):
			current_block = hex_text[i * hex_block_size: (i + 1) * hex_block_size]
			decrypted_message += self.decrypt_block(current_block)

		decrypted_message = remove_padding(decrypted_message)

		return hex_to_ascii(decrypted_message)

	def print_matrix_in_hex(self, state_matrix):
		for i in range(self.rows):
			for j in range(self.cols):
				print(state_matrix[i][j].get_hex_string_from_bitvector(), end=" ")
			print()


def main():
	plain_text = input('Enter plain text: ')
	key = input('Enter key: ')
	mode = int(input('Enter AES mode (128/192/256): '))

	t1 = time.time()
	aes = AES(key, mode)
	t2 = time.time()
	cipher = aes.encrypt(plain_text)
	t3 = time.time()
	decipher_text = aes.decrypt(cipher)
	t4 = time.time()

	print('Plain Text:')
	print(plain_text, '[In ASCII]')
	print(ascii_to_hex(plain_text), '[In HEX]')
	print('\n')

	print('Key:')
	print(hex_to_ascii(aes.key), '[In ASCII]')
	print(aes.key, '[In HEX]')
	print('\n')

	print('Cipher text:')
	print(ascii_to_hex(cipher), '[In HEX]')
	print(cipher, '[In ASCII]')
	print('\n')

	print('Deciphered Text:')
	print(ascii_to_hex(decipher_text), '[In HEX]')
	print(decipher_text, ['IN ASCII'])
	print('\n')

	print('Execution Time')
	print('Key Scheduling:', (t2-t1))
	print('Encryption Time:', (t3-t2))
	print('Decryption Time:', (t4-t3))


if __name__ == '__main__':
	main()
