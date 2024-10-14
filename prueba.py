import base64
from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes

# Función para convertir una clave pública a un formato tipo PEM
def elgamal_public_key_to_pem(key):
    key_data = {
        'p': key.p,
        'g': key.g,
        'y': key.y
    }

    key_str = f"-----BEGIN ELGAMAL PUBLIC KEY-----\n"
    for component, value in key_data.items():
        key_str += f"{component}: {value}\n"
    key_str += "-----END ELGAMAL PUBLIC KEY-----"

    return key_str

# Función para convertir de "PEM" a bytes
def pem_to_bytes(pem_string):
    return pem_string.encode('utf-8')

# Función para restaurar una clave pública desde un "PEM" simple
def pem_to_elgamal_public_key(pem_string):
    # Parsear los componentes de la clave
    components = {}
    lines = pem_string.splitlines()
    for line in lines:
        if ':' in line:
            key, value = line.split(': ')
            components[key] = int(value)

    # Reconstruir la clave pública
    key = ElGamal.construct((components['p'], components['g'], components['y']))
    return key

# Generar clave pública y privada ElGamal
key = ElGamal.generate(1024, get_random_bytes)
public_key = key.publickey()

# Convertir la clave pública a un formato tipo PEM
public_key_pem = elgamal_public_key_to_pem(public_key)
print(public_key_pem)

# Convertir el "PEM" a bytes para enviar
public_key_bytes = pem_to_bytes(public_key_pem)

# Ahora enviarías `public_key_bytes` por el socket
print(f"Clave pública en bytes: {public_key_bytes}")

# En el lado receptor, convertir de bytes a "PEM" y luego restaurar la clave
restored_public_key_pem = public_key_bytes.decode('utf-8')
restored_public_key = pem_to_elgamal_public_key(restored_public_key_pem)

print(f"Clave pública restaurada: p={restored_public_key.p}, g={restored_public_key.g}, y={restored_public_key.y}")