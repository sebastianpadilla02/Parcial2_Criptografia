import json
import socket
import threading
from funciones import Crypto_functions, Diffie_Hellman

key = None  # Define key as None
u = None  # Para almacenar el valor recibido del servidor

def recibir_mensajes(client_socket):
    global key
    try:
        while True:
            # Recibir el mensaje del servidor
            data = client_socket.recv(1024)
            if not data:
                break

            # Extraer el nonce del mensaje
            nonce = data[:8]  # Asumimos que el nonce es de 8 bytes
            encrypted_message = data[8:]  # El mensaje encriptado (sin el nonce)

            # Desencriptar el mensaje
            desencriptado = Crypto_functions.Salsa20_decrypt(key, nonce, encrypted_message)

            # Limpiar la línea de entrada del cliente para evitar interferencias
            print("\r" + " " * 80, end="")  # Borrar la línea actual
            print(f"\rServidor: {desencriptado.decode('utf-8')}")  # Imprimir mensaje del servidor

            # Volver a mostrar el prompt para el cliente
            print("Cliente: ", end="", flush=True)
    except Exception as e:
        print(f"Error en recibir_mensajes: {e}")
    finally:
        client_socket.close()


def iniciar_cliente():
    global key, u  # Hacer referencia a las variables globales

    # Cargar el archivo JSON con los parámetros p, q, g
    with open('parameters.json') as f:
        data = json.load(f)

    # Acceder a un único conjunto de parámetros, por ejemplo, el primero
    param_set = data["parameters"][2]  # Cambia el índice a 0, 1, 2... según el conjunto que quieras

    # Acceder a los valores de p, q y g
    p = param_set["p"]
    q = param_set["q"]
    g = param_set["g"]

    print(f"Conjunto seleccionado: p={p}, q={q}, g={g}")

    # Inicializar Diffie-Hellman con los parámetros p y g
    key_diffie = Diffie_Hellman(p, q, g)

    # Generar v = g^β (clave pública del cliente)
    v = key_diffie.generate_public_key()

    # Crear un socket para el cliente
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #client_socket.connect(('172.20.10.2', 8080))  # Cambia por la IP del servidor
    client_socket.connect(('127.0.0.1', 8080))  # Cambia por la IP del servidor

    # Esperar a recibir u del servidor
    u_bytes = client_socket.recv(1024)
    u = int.from_bytes(u_bytes, 'big')
    print(f"Recibido u del servidor: {u}")

    # Enviar v al servidor
    print(f"Enviando v al servidor: {v}")
    client_socket.send(v.to_bytes((v.bit_length() + 7) // 8, 'big'))

    # Calcular la clave compartida w = u^β
    key = key_diffie.generate_shared_secret(u)
    print(f"Clave compartida generada: {key}")

    # Hilo para recibir mensajes del servidor
    thread = threading.Thread(target=recibir_mensajes, args=(client_socket,))
    thread.daemon = True  # Asegurar que el hilo se detenga cuando el programa finalice
    thread.start()

    while True:
        # Verificar que se haya calculado la clave antes de enviar un mensaje
        # if key is None:
        #     print("Esperando la clave compartida...")
        #     continue

        # Enviar mensaje al servidor
        try:
            message = input("Cliente: ")
            if message.lower() == 'salir':
                print("Cerrando conexión...")
                client_socket.close()
                break

            # Generar un nuevo nonce para el mensaje
            nonce = Crypto_functions.generar_nonce()

            # Encriptar el mensaje usando la clave compartida
            encriptar = Crypto_functions.Salsa20_encrypt(key, nonce, message.encode('utf-8'))

            # Enviar el nonce y el mensaje encriptado
            client_socket.send(nonce + encriptar)
        except Exception as e:
            print(f"Error al enviar mensaje: {e}")
            client_socket.close()
            break


if __name__ == "__main__":
    iniciar_cliente()
