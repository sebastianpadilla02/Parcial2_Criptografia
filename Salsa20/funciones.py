from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import Salsa20

class Diffie_Hellman:
    def __init__(self, p=None, g=None):
        # Si no se proveen p y g, asignamos valores predeterminados (por ejemplo, para un grupo de Diffie-Hellman conocido)
        self.p = p or 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDFB6237AD5B7E2077F4ECFB149293B63240C0B5DFF53B6F937A1A93DBA4BFF8F6B1A457E9F198EF49F5F56250A09D  # Un valor grande primo
        self.g = g or 2  # Generador predeterminado
        self.private_key = get_random_bytes(32)  # Generar una clave privada aleatoria de 256 bits (32 bytes)
        self.public_key = None

    # Función para realizar la exponenciación modular
    def mod_exp(self, base, exponent, mod):
        return pow(base, exponent, mod)

    # Genera la clave pública
    def generate_public_key(self):
        self.public_key = self.mod_exp(self.g, int.from_bytes(self.private_key, 'big'), self.p)
        return self.public_key

    # Calcula la clave compartida usando la clave pública de la otra parte
    def generate_shared_secret(self, other_public_key):
        shared_key = self.mod_exp(other_public_key, int.from_bytes(self.private_key, 'big'), self.p)
        # Convertimos el shared_key a bytes para ser usado como clave de cifrado
        return shared_key.to_bytes(32, 'big')  # 32 bytes es lo típico para claves de cifrado

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

