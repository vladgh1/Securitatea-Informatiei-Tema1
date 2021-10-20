import secrets
import sys
from Crypto.Cipher import AES

KEY_LEN_BYTES = 16		# Must be 16, 24 or 32
FILE_BLOCK_SIZE = 32 	# multiple of 16

init_vector = secrets.token_bytes(FILE_BLOCK_SIZE)
k_prime = secrets.token_bytes(KEY_LEN_BYTES)

def byte_xor(ba1, ba2):
	# Returns ba1 xor ba2 as a byte array
	return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


class KM:
	def __init__(self, alg):
		self.alg = alg


	def get_algorithm(self):
		return self.alg


	def generate_encryption_key(self):
		cipher = AES.new(k_prime, AES.MODE_ECB)
		return cipher.encrypt(secrets.token_bytes(KEY_LEN_BYTES))


class A:
	# Message to do xor with on CBC algorithm
	xor_message = init_vector

	def __init__(self, key_manager):
		self.km = key_manager


	def set_destination(self, destination):
		self.destination = destination


	def encrypt_text(self, text):
		cipher = AES.new(self.encryption_key, AES.MODE_ECB)
		return cipher.encrypt(text)


	def decrypt_key(self, key):
		decipher = AES.new(k_prime, AES.MODE_ECB)
		return decipher.decrypt(key)


	def set_algorithm(self, alg):
		# Set algotithm for self and destination
		self.alg = alg
		self.destination.set_algorithm(alg)

		# Get encrytion key from key manager for self and destination
		self.encryption_key_enc = km.generate_encryption_key()
		self.destination.set_encryption_key(self.encryption_key_enc)
		self.encryption_key = self.decrypt_key(self.encryption_key_enc)


	def set_file(self, file):
		self.file = file


	def request(self):
		file = open(self.file, 'r')
		# Reads the content of a file block by block
		while True:
			text = file.read(FILE_BLOCK_SIZE)

			# Breaks if no content left
			if not text:
				break

			# Text should be multiple by 16 long
			text += '\0' * ((FILE_BLOCK_SIZE - len(text)) % FILE_BLOCK_SIZE)

			# Apply xor if CBC algorithm is using
			if self.alg == 'CBC':
				text = byte_xor(bytes(text, 'utf-8'), self.xor_message)

			# Send encrypted block tewt to destination
			encrypted_text = self.encrypt_text(text)
			self.destination.send(encrypted_text)

			# Set next message for xor for CBC algorithm
			self.xor_message = encrypted_text



class B:
	text = ''
	xor_message = init_vector
	def set_source(self, source):
		self.source = source


	def set_algorithm(self, alg):
		self.alg = alg


	def decrypt_text(self, text):
		decipher = AES.new(self.encryption_key, AES.MODE_ECB)
		return decipher.decrypt(text)


	def decrypt_key(self, key):
		decipher = AES.new(k_prime, AES.MODE_ECB)
		return decipher.decrypt(key)


	def set_encryption_key(self, key):
		self.encryption_key = self.decrypt_key(key)


	def request(self):
		# Request data from source
		self.source.request()


	def send(self, text):
		# Recieve an encrypted text block from source
		recieve = self.decrypt_text(text)

		# Apply xor on message if CBC algorithm is used
		if self.alg == 'CBC':
			xor_message = text
			recieve = byte_xor(recieve, self.xor_message)
			self.xor_message = xor_message

		# Append decrypted text block previously decrypted text
		self.text += recieve.decode('utf-8')


	def print(self):
		print(self.text)


# Checks for arguments validity
if (len(sys.argv) != 3):
	print(f'Invalid usage: type `python3 {sys.argv[0]} (file) (ECB|CBC)`')
	exit(1)

if (sys.argv[2] not in {'CBC', 'ECB'}):
	print('Unknown encryption method')
	exit(2)


# Prepares the instances
km = KM(sys.argv[2])
a = A(km)
b = B()
a.set_file(sys.argv[1])
a.set_destination(b)
b.set_source(a)
a.set_algorithm(km.get_algorithm())

# Request to recieve data and print it on the screen
b.request()
b.print()