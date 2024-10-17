import json
import gensafeprime
from Crypto.Util import number

class Parametros:
    def __init__(self, n_bits):
        p = gensafeprime.generate(n_bits)
        q = (p-1) // 2

        g = number.getRandomNBitInteger(n_bits) % p
        while(pow(g, 2, p) == 1 or pow(g, q, p) != 1):
            g = number.getRandomNBitInteger(n_bits) % p

        self.p = p
        self.q = q
        self.g = g
        
        self.crear_json('Cifrado_asimetrico/ElGamal/parametros.json')


    # Función para crear el archivo JSON con nuevos parámetros
    def crear_json(self, archivo_json):
        nuevo_parametro = {
            "p": self.p,
            "q": self.q,
            "g": self.g
        }

        # Crear un nuevo archivo con los nuevos parámetros
        datos = {"parameters": [nuevo_parametro]}

        # Guardar los nuevos valores en el archivo JSON (sobrescribir el archivo existente)
        with open(archivo_json, 'w') as file:
            json.dump(datos, file, indent=4)

        # print(f"Archivo {archivo_json} creado y actualizado con nuevos parámetros.")