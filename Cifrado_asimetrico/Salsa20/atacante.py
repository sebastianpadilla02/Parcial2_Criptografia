import yaml
from funciones import Crypto_functions, Diffie_Hellman
import json
import math
import base64

y = None

def pasos_bebe_pasos_gigante(g, y, p):  #g:Generador conocido, y: u o v capturado, n: p-1)
    m = math.ceil(math.sqrt(p-1))

    R = {}
    # Paso de bebé: Precalcular los valores de g^j mod p y almacenarlos en un diccionario
    for j in range(m):
        R[pow(g, j, p)] = j

    # Paso de gigante: Calcular g^(-m) mod p
    B = pow(g, -m, p)

    Y = y

    for i in range(m):
        if Y in R:
            x = i * m + R[Y]
            return x
        
        Y = (Y * B) % p

    return None


import base64

def leer_y_extraer_mensajes_yaml(ruta_archivo, p, q, g):
    with open(ruta_archivo, 'r') as file:
        contenido_yaml = yaml.safe_load(file)  # Leer y cargar el archivo YAML

    publico = False
    privado = False
    key = None

    # Iterar sobre los paquetes y extraer los datos
    for packet in contenido_yaml['packets']:

        datos_base64 = packet['data']  # Extraer el dato en base64

        try:
            # print(f"datos base 64: {datos_base64}")

            if not publico:
                # Convertir los datos de bytes a entero para 'u'
                u = int.from_bytes(datos_base64, 'big')
                publico = True

                # Usar el valor de 'u' en el algoritmo de pasos de bebé y gigante
                x = pasos_bebe_pasos_gigante(g, u, p)
                if x is None:
                    print("No se pudo encontrar el valor de alpha")
                    return None
                
                continue

            if not privado:
                key_diffie2 = Diffie_Hellman(p, q, g)
                key_diffie2.alpha = x

                # Convertir los datos de bytes a entero para 'v'
                v = int.from_bytes(datos_base64, 'big')

                # Calcular la clave compartida w = u^β
                w = key_diffie2.generate_shared_secret(v)
                print(f"Clave compartida generada: {w}")

                key = Crypto_functions.KDF(w)
                print(f"Llave definitiva: {key}")
                privado = True
                continue

            # Extraer el nonce del mensaje (asumimos que son los primeros 8 bytes)
            nonce = datos_base64[:8]  # El nonce es de 8 bytes
            encrypted_message = datos_base64[8:]  # El mensaje cifrado es el resto

            # Desencriptar el mensaje
            desencriptado = Crypto_functions.Salsa20_decrypt(key, nonce, encrypted_message)
            if packet['peer'] == 1:
                print(f"Servidor: {desencriptado.decode('utf-8')}")
            else:
                print(f"Cliente: {desencriptado.decode('utf-8')}")
        
        except Exception as e:
            print(f"Error al procesar el paquete: {e}")
            continue

            
# Cargar el archivo JSON con los parámetros p, q, g
with open('parameters.json') as f:
    data = json.load(f)

# Acceder a un único conjunto de parámetros, por ejemplo, el primero
param_set = data["parameters"][4]  # Cambia el índice a 0, 1, 2... según el conjunto que quieras

# Acceder a los valores de p, q y g
p = param_set["p"]
q = param_set["q"]
g = param_set["g"]

print(f"Conjunto seleccionado: p={p}, q={q}, g={g}")

# Ruta del archivo YAML
ruta_archivo_yaml = 'Diffie5.yaml'  # Cambia esto con la ruta correcta

# Leer y extraer mensajes del archivo YAML
leer_y_extraer_mensajes_yaml(ruta_archivo_yaml, p, q ,g)
