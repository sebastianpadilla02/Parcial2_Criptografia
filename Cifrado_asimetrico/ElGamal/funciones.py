from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import Salsa20
import random
import hashlib

class ElGamal:
    def __init__(self, p: int, q: int, g: int):
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

    def mod_exp(self, base, exponent, mod):
        return pow(base, exponent, mod)

    def generar_alpha(self) -> int:
        alpha = random.randrange(2, self.q)
        return alpha

    def generate_public_key(self):
        u = self.mod_exp(self.g, self.alpha, self.p)
        return u

    def EEG(self, mensaje):
        # Convertir el mensaje en un entero grande para cifrar
        mensaje_entero = int.from_bytes(mensaje, 'big')

        # Escoger un valor aleatorio para beta
        beta = random.randint(2, self.q)

        # Calcular v = g^beta mod p
        v = self.mod_exp(self.g, beta, self.p)

        # Calcular w = pk^beta mod p
        w = self.mod_exp(self.public_key, beta, self.p)

        # Encriptar el mensaje
        c = (mensaje_entero * w) % self.p

        # Convertir v y c a bytes
        v_bytes = v.to_bytes((v.bit_length() + 7) // 8, 'big')
        c_bytes = c.to_bytes((c.bit_length() + 7) // 8, 'big')

        # Incluir la longitud de v para evitar problemas al deserializar
        len_v_bytes = len(v_bytes).to_bytes(4, 'big')

        # Retornar el tamaño de v seguido de v y c
        return len_v_bytes + v_bytes + c_bytes

    def DEG(self, data):
        try:
            # Obtener los primeros 4 bytes que indican el tamaño de v
            len_v = int.from_bytes(data[:4], 'big')

            # Extraer v_bytes y c_bytes
            v_bytes = data[4:4 + len_v]
            c_bytes = data[4 + len_v:]

            # Convertir de bytes a enteros
            v = int.from_bytes(v_bytes, 'big')
            c = int.from_bytes(c_bytes, 'big')

            # Calcular w = v^sk mod p
            w = self.mod_exp(v, self.private_key, self.p)

            # Calcular w inverso (inverso modular de w)
            w_inv = self.mod_exp(w, self.p - 2, self.p)  # Usando teorema de Fermat

            # Desencriptar el mensaje
            mensaje_entero = (c * w_inv) % self.p

            # Convertir el mensaje entero de nuevo a bytes
            mensaje_bytes = mensaje_entero.to_bytes((mensaje_entero.bit_length() + 7) // 8, 'big')

            return mensaje_bytes
        except Exception as e:
            print(f"Error al desencriptar: {e}")
            return b""