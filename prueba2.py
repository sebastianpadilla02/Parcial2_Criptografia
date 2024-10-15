from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import Salsa20
import random
import hashlib

class ElGamal:
    def __init__(self, p: int, q: int,  g: int):
        # Si no se proveen p y g, asignamos valores predeterminados (por ejemplo, para un grupo de Diffie-Hellman conocido)
        self.p = p 
        self.q = q
        self.g = g
        self.alpha = None
        self.public_key = None
        self.private_key = None

    def GEG(self):
        self.alpha = self.generar_alpha()
        self.public_key = self.generate_public_key()
        self.private_key = self.alpha
        return self.public_key, self.private_key

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

    # Función EEG: Encriptar el mensaje
    def EEG(self, mensaje):
        # Escoger un valor aleatorio para beta
        beta = random.randint(2, self.q)  # Valor aleatorio para encriptar

        # Calcular v = g^beta mod p
        v = self.mod_exp(self.g, beta, self.p)

        # Calcular w = pk^beta mod p
        w = self.mod_exp(self.public_key, beta, self.p)

        # Encriptar el mensaje m (multiplicación mod p)
        c = (mensaje * w) % self.p

        # Retornar el par (v, c)
        return v, c

    def DEG(self, v, c):

        #Necesito separar v y c de mensaje_c

        w = self.mod_exp(v, self.private_key, self.p)

        # Calcular w inverso (inverso modular de w)
        w_inv = self.mod_exp(w, self.p-2, self.p)  # Usando teorema de Fermat

        m = (c * w_inv) % self.p

        return m
    

# Ejemplo de uso:
if __name__ == "__main__":

    criptosistema = ElGamal(227, 113, 12)
    # Generar las claves
    pk, sk = criptosistema.GEG()
    print(f"Clave pública (pk): {pk}")
    print(f"Clave privada (sk): {sk}")

    # Mensaje a encriptar
    mensaje = 15  # Un número entero como mensaje
    print(f"Mensaje original: {mensaje}")

    # Encriptar el mensaje
    v, c = criptosistema.EEG(mensaje)
    print(f"Mensaje cifrado: v = {v}, c = {c}")

    # Desencriptar el mensaje
    mensaje_descifrado = criptosistema.DEG(v, c)
    print(f"Mensaje descifrado: {mensaje_descifrado}")