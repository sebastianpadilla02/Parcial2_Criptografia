import socket
import threading
import json

from funciones import Crypto_functions, Diffie_Hellman

key = None  # Define key as None

def manejar_cliente(client_socket):
    global key

    try:
        while True:
            # Recibir mensaje del cliente
            data = client_socket.recv(1024)
            if not data:
                break

            # Extraer el nonce del mensaje
            nonce = data[:8]  # Asumimos que el nonce es de 24 bytes
            encrypted_message = data[8:]  # El mensaje encriptado (sin el nonce)

            # Desencriptar el mensaje
            desencriptar = Crypto_functions.Salsa20_decrypt(key, nonce, encrypted_message)
            print(f"Cliente: {desencriptar.decode('utf-8')}")

            # Enviar respuesta al cliente
            response = input("Servidor: ")

            # Generar un nuevo nonce para la respuesta
            nonce = Crypto_functions.generar_nonce()
            encriptar = Crypto_functions.Salsa20_encrypt(key, nonce, response.encode('utf-8'))

            # Enviar el nonce y el mensaje encriptado
            client_socket.send(nonce + encriptar)
    except Exception as e:
        print(f"Error en enviar_recibir_mensajes: {e}")
    finally:
        client_socket.close()

def iniciar_servidor():
    global key

    # Crear un socket para el servidor
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 8080))
    server_socket.listen(1)
    print("Esperando conexión...")

    # Aceptar la conexión del cliente
    client_socket, client_address = server_socket.accept()
    print(f"Conectado con {client_address}")

    # Cargar el archivo JSON con los parámetros p, q, g
    with open('parameters.json') as f:
        data = json.load(f)

    # Acceder a un único conjunto de parámetros, por ejemplo, el primero
    param_set = data["parameters"][1]  # Cambia el índice a 0, 1, 2... según el conjunto que quieras

    # Acceder a los valores de p, q y g
    p = param_set["p"]
    q = param_set["q"]
    g = param_set["g"]

    # print(f"Conjunto seleccionado: p={p}, q={q}, g={g}")

    # Iniciar Diffie-Hellman con los parámetros p y g
    key_change = Diffie_Hellman(p, q, g)

    # Generar u = g^α (clave pública del servidor)
    u = key_change.generate_public_key()

    # Enviar u al cliente
    # print(f"Enviando u al cliente: {u}")
    client_socket.send(u.to_bytes((u.bit_length() + 7) // 8, 'big'))

    # Esperar el valor v = g^β del cliente
    v_bytes = client_socket.recv(1024)
    v = int.from_bytes(v_bytes, 'big')
    # print(f"Recibido v del cliente: {v}")

    # Calcular la clave compartida w = v^α (clave compartida)
    w = key_change.generate_shared_secret(v)
    # print(f"Clave compartida generada: {w}")

    key = Crypto_functions.KDF(w)
    # print(f"Llave definitiva: {key}")

    # Continuar con el manejo del cliente
    manejar_cliente(client_socket)
    server_socket.close()
    print("server_socket cerrado")

if __name__ == "__main__":
    iniciar_servidor()
