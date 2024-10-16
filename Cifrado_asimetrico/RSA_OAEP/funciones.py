from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class RSA_OAEP:
    def __init__(self):
        # Generar claves RSA
        key = RSA.generate(2048)
        self.private_key = key
        self.public_key = key.publickey()
        self.cifrador_privado = None
        self.cifrador_publico = None

    def desencriptar(self, mensaje):
        desencriptado = self.cifrador_privado.decrypt(mensaje)
        return desencriptado

    def encriptar(self, mensaje):
        encriptado = self.cifrador_publico.encrypt(mensaje)
        return encriptado

    def importar(self, public_key_bytes):
        return RSA.import_key(public_key_bytes)
    
    def actualizar(self):
        self.cifrador_publico = PKCS1_OAEP.new(self.public_key)
        self.cifrador_privado = PKCS1_OAEP.new(self.private_key)
