import yaml
from funciones import Crypto_functions, Diffie_Hellman
import json
import math

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


def leer_y_extraer_mensajes_yaml(ruta_archivo, p, q, g):
    with open(ruta_archivo, 'r') as file:
        contenido_yaml = yaml.safe_load(file)  # Leer y cargar el archivo YAML

    publico = False
    privado = False
    # Iterar sobre los paquetes y extraer los datos
    for packet in contenido_yaml['packets']:
        datos_base64 = packet['data']  # Extraer el dato en base64
        if(publico == False):
            u = datos_base64
            publico = True

            x = pasos_bebe_pasos_gigante(g, u, p)
            if(x == None):
                print("No se pudo encontrar el valor de alpha")
                return None
            
            continue

        if (privado == False):
            key_diffie2 = Diffie_Hellman(p, q, g)
            key_diffie2.alpha = x
            v = datos_base64
            # Calcular la clave compartida w = u^β
            w = key_diffie2.generate_shared_secret(v)
            print(f"Clave compartida generada: {w}")

            key = Crypto_functions.KDF(w)
            print(f"Llave definitiva: {key}")
            privado = True
            
        # Extraer el nonce del mensaje
        nonce = datos_base64[:8]  # Asumimos que el nonce es de 8 bytes
        encrypted_message = datos_base64[8:]

        # Desencriptar el mensaje
        desencriptado = Crypto_functions.Salsa20_decrypt(key, nonce, encrypted_message)
        if(packet['peer'] == 1):
            print(f"Servidor: {desencriptado.decode('utf-8')}")
        else:
            print(f"Cliente: {desencriptado.decode('utf-8')}")
            
# Cargar el archivo JSON con los parámetros p, q, g
with open('parameters.json') as f:
    data = json.load(f)

# Acceder a un único conjunto de parámetros, por ejemplo, el primero
param_set = data["parameters"][0]  # Cambia el índice a 0, 1, 2... según el conjunto que quieras

# Acceder a los valores de p, q y g
p = param_set["p"]
q = param_set["q"]
g = param_set["g"]

print(f"Conjunto seleccionado: p={p}, q={q}, g={g}")

# Ruta del archivo YAML
ruta_archivo_yaml = 'Diffie1.yaml'  # Cambia esto con la ruta correcta

# Leer y extraer mensajes del archivo YAML
leer_y_extraer_mensajes_yaml(ruta_archivo_yaml, p, q ,g)
