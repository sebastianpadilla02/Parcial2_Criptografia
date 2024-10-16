from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import Salsa20
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

class Diffie_Hellman:
    def __init__(self):
        self.alpha = self.generar_alpha()
        self.U = self.generate_public_key()

    def generar_alpha(self):
        alpha = ec.generate_private_key(ec.SECP256R1(), default_backend())  # P256
        return alpha
    
    def generate_public_key(self):
        U = self.alpha.public_key()
        return U

    def public_key_to_bytes(self):
        U_bytes = self.U.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return U_bytes
    
    def convert_bytes_to_key(self, V):
        return serialization.load_der_public_key(V, backend=default_backend())

    # Calcula la clave compartida usando la clave pública de la otra parte
    def generate_shared_secret(self, other_public_key):
        return self.alpha.exchange(ec.ECDH(), other_public_key)

class Crypto_functions:
    # Clave de 16 bytes (128 bits), 24 bytes (192 bits) o 32 bytes (256 bits)
    def generar_clave_AES():
        clave = get_random_bytes(32)
        return clave

    def generar_iv_AES():
        iv = get_random_bytes(16)
        return iv

    def generar_nonce():
        nonce = get_random_bytes(8)
        return nonce

    def AES_ECB_encrypt(key, texto_original):
        cipher = AES.new(key, AES.MODE_ECB)
        texto_padded = pad(texto_original, AES.block_size)
        texto_encriptado = cipher.encrypt(texto_padded)
        return texto_encriptado

    def AES_ECB_decrypt(key, texto_encriptado):
        cipher = AES.new(key, AES.MODE_ECB)
        texto_desencriptado = cipher.decrypt(texto_encriptado)
        texto_desencriptado = unpad(texto_desencriptado, AES.block_size)
        return texto_desencriptado

    def AES_CBC_encrypt(key, iv, texto_original):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        texto_padded = pad(texto_original, AES.block_size)
        texto_encriptado = cipher.encrypt(texto_padded)
        return texto_encriptado

    def AES_CBC_decrypt(key, iv, texto_encriptado):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        texto_desencriptado = cipher.decrypt(texto_encriptado)
        texto_desencriptado = unpad(texto_desencriptado, AES.block_size)
        return texto_desencriptado

    def AES_CTR_encrypt(key, iv, texto_original):
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
        texto_encriptado = cipher.encrypt(texto_original)
        return texto_encriptado

    def AES_CTR_decrypt(key, iv, texto_encriptado):
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
        texto_desencriptado = cipher.decrypt(texto_encriptado)
        return texto_desencriptado

    def ChaCha20_encrypt(key, iv, texto_original):
        cipher = ChaCha20.new(key=key, nonce=iv)
        texto_encriptado = cipher.encrypt(texto_original)
        return texto_encriptado

    def ChaCha20_decrypt(key, iv, texto_encriptado):
        cipher = ChaCha20.new(key=key, nonce=iv)
        texto_desencriptado = cipher.decrypt(texto_encriptado)
        return texto_desencriptado

    def Salsa20_encrypt(key, iv, texto_original):
        cipher = Salsa20.new(key=key, nonce=iv)
        texto_encriptado = cipher.encrypt(texto_original)
        return texto_encriptado

    def Salsa20_decrypt(key, iv, texto_encriptado):
        cipher = Salsa20.new(key=key, nonce=iv)
        texto_desencriptado = cipher.decrypt(texto_encriptado)
        return texto_desencriptado

    def KDF(w):
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # Clave de 32 bytes (256 bits)
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(w)

        return derived_key