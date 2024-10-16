from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import Salsa20
import random
import hashlib

class Diffie_Hellman:
    def __init__(self, p: int, q: int,  g: int):
        # Si no se proveen p y g, asignamos valores predeterminados (por ejemplo, para un grupo de Diffie-Hellman conocido)
        self.p = p 
        self.q = q
        self.g = g
        self.alpha = self.generar_alpha()

    # Función para realizar la exponenciación modular
    def mod_exp(self, base, exponent, mod):
        return pow(base, exponent, mod)

    def generar_alpha(self) -> int:
        # Generar un número aleatorio en el rango [2, q-1]
        alpha = random.randrange(2, self.q)
        return alpha
    
    def generate_public_key(self):
        u = self.mod_exp(self.g, self.alpha, self.p)
        return u

    # Calcula la clave compartida usando la clave pública de la otra parte
    def generate_shared_secret(self, other_public_key: int) -> int:
        shared_key = self.mod_exp(other_public_key, self.alpha, self.p)
        # Convertimos el shared_key a bytes para ser usado como clave de cifrado
        return shared_key  # 32 bytes es lo típico para claves de cifrado

class Crypto_functions:
    # Clave de 16 bytes (128 bits), 24 bytes (192 bits) o 32 bytes (256 bits)
    def generar_clave_AES() -> bytes:
        clave = get_random_bytes(32)
        return clave

    def generar_nonce() -> bytes:
        nonce = get_random_bytes(8)
        return nonce

    # IV de 16 bytes (128 bits) o 8 bytes (64 bits) para AES y ChaCha20 respectivamente 
    def generar_IV_AES(tamano_IV: int) -> bytes:
        IV = get_random_bytes(tamano_IV)
        return IV

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

    def KDF(w, iterations = 1000, dklen= 32):
        # Derivar la clave sin sal y con iteraciones mínimas
        key = hashlib.pbkdf2_hmac(
            'sha256',            # Algoritmo hash
            w.to_bytes((w.bit_length() + 7) // 8, byteorder='big'),   # Contraseña en formato bytes
            b'',                 # Sal vacía
            iterations,          # Número de iteraciones (1000 o más es recomendable)
            dklen=dklen          # Longitud de la clave derivada (32 bytes para Salsa20)
        )

        return key