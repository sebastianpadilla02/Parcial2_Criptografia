from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import Salsa20
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256


class ElGamal_functions:
    def __init__(self):
        key = ElGamal.generate(1024, get_random_bytes)
        self.private_key = key
        self.public_key = key.publickey()

    def desencriptar(self, mensaje):
        desencriptado = self.private_key.decrypt(mensaje)
        return desencriptado

    def encriptar(self, mensaje):
        encriptado = self.public_key.encrypt(mensaje, 32)
        return encriptado
    
    # def actualizar(self):
    #     self.cifrador_publico = PKCS1_OAEP.new(self.public_key)
    #     self.cifrador_privado = PKCS1_OAEP.new(self.private_key)
