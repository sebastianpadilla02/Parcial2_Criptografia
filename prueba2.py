from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import Salsa20
import random
import hashlib

class ElGamal:
    def __init__(self, p: int, q: int,  g: int):
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
        # Calcular w = v^sk mod p
        w = self.mod_exp(v, self.private_key, self.p)

        # Calcular w inverso (inverso modular de w)
        w_inv = self.mod_exp(w, self.p-2, self.p)  # Usando teorema de Fermat

        # Desencriptar el mensaje
        m = (c * w_inv) % self.p

        return m
    

# Ejemplo de uso:
if __name__ == "__main__":

    # criptosistema = ElGamal(227, 113, 12)
    criptosistema = ElGamal(p = 137264501074495181280555132673901931323332164724815133317526595627537522562067022989603699054588480389773079016561323343477054349336451609284971148159280724829128531552270321268457769520042856144429883077983691811201653430137376919960068969990507421437958462547891425943025305810160065324145921753228735283903,
			q = 68632250537247590640277566336950965661666082362407566658763297813768761281033511494801849527294240194886539508280661671738527174668225804642485574079640362414564265776135160634228884760021428072214941538991845905600826715068688459980034484995253710718979231273945712971512652905080032662072960876614367641951,
			g = 40746562294764965373407784234554073062674073565341303353016758609344799210654104763969824808430330931109448281620048720300276969942539907157417365502013807736680793541720602226570436490901677489617911977499169334249484471027700239163555304280499401445437347279647322836086848012965178946904650279473615383579)
    # Generar las claves
    pk, sk = criptosistema.GEG()
    print(f"Clave pública (pk): {pk}")
    print(f"Clave privada (sk): {sk}")

    # Mensaje a encriptar
    mensaje = 'hola'
    mensaje_entero = int.from_bytes(mensaje.encode('utf-8'), 'big')  # Convertir mensaje a entero
    print(f"Mensaje original como entero: {mensaje_entero}")

    # Encriptar el mensaje
    v, c = criptosistema.EEG(mensaje_entero)
    print(f"Mensaje cifrado: v = {v}, c = {c}")

    # Desencriptar el mensaje
    mensaje_descifrado_entero = criptosistema.DEG(v, c)
    print(f'Mensajes descifrado como entero: {mensaje_descifrado_entero}')
    mensaje_descifrado = mensaje_descifrado_entero.to_bytes((mensaje_descifrado_entero.bit_length() + 7) // 8, 'big').decode('utf-8')
    print(f"Mensaje descifrado: {mensaje_descifrado}")
