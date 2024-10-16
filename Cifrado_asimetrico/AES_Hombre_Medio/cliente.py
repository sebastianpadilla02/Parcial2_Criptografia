import socket
import threading
from funciones import Crypto_functions, Diffie_Hellman

key = None  # Definir la clave como None inicialmente

#Función para leer la clave desde un archivo
def leer_clave_desde_archivo(file_path):
    try:
        with open(file_path, 'rb') as file:
            return file.read()  # Leer la clave en formato binario
    except Exception as e:
        print(f"Error al leer el archivo de clave: {e}")
        return None

#Función para recibir mensajes del servidor
def recibir_mensajes(client_socket):
    global key
    try:
        while True:
            # Recibir el mensaje del servidor
            data = client_socket.recv(1024)

            # Espera de mensaje del servidor
            if not data:
                break

            # Extraer el nonce(iv) del mensaje
            iv = data[:16]  # Asumimos que el nonce(iv) es de 16 bytes (para AES)
            encrypted_message = data[16:] # El mensaje encriptado

            # Desencriptar el mensaje
            desencriptado = Crypto_functions.AES_CBC_decrypt(key, iv, encrypted_message)

            # Limpiar la línea de entrada del cliente para evitar interferencias, e imprimir el mensaje del servidor
            print(f"\rServidor: {desencriptado.decode('utf-8')}")
            print("Cliente: ", end="", flush=True)
    except Exception as e:
        print(f"Error en recibir_mensajes: {e}")
    finally:
        # Cerrar el socket del cliente
        client_socket.close()

def iniciar_cliente():
    global key  # Hacer referencia a la variable global `key`

    # Inicializar Diffie-Hellman
    key_diffie = Diffie_Hellman()

    V = key_diffie.U

    # Crear un socket para el cliente
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 8081))
    # client_socket.connect(('192.168.230.34', 8080)) # Conectar al servidor, necesario cambiar la IP para pruebas en diferentes equipos

    # Esperar a recibir U del servidor(ALICE)
    U_bytes = client_socket.recv(1024)
    # print(f"Recibido U del servidor: {U_bytes}")

    U = key_diffie.convert_bytes_to_key(U_bytes)

    # Enviar V al servidor
    V_bytes = key_diffie.public_key_to_bytes()
    # print(f"Enviando V al servidor: {V_bytes}")
    client_socket.send(V_bytes)

    # Calcular el secreto compartido W
    W = key_diffie.generate_shared_secret(U)
    # print(f"Clave compartida generada: {W}")

    key = Crypto_functions.KDF(W)
    # print(f"Llave definitiva: {key}")

    # Hilo para recibir mensajes del servidor
    thread = threading.Thread(target=recibir_mensajes, args=(client_socket,))
    thread.daemon = True  # Hilo en segundo plano para no bloquear
    thread.start()

    while True:
        # Verificar que se haya cargado la clave antes de enviar un mensaje
        if key is None:
            print("Esperando la clave...")
            continue

        # Enviar mensaje al servidor
        try:
            # Leer el mensaje ingresado por el cliente
            message = input("Cliente: ")
            if message.lower() == 'salir':
                print("Cerrando conexión...")
                client_socket.close()
                break

            # Generar un nuevo nonce (IV) para el mensaje
            iv = Crypto_functions.generar_iv_AES()

            # Encriptar el mensaje
            encriptar = Crypto_functions.AES_CBC_encrypt(key, iv, message.encode('utf-8'))

            # Enviar el nonce y el mensaje encriptado
            client_socket.send(iv + encriptar)
        except Exception as e:
            print(f"Error al enviar mensaje: {e}")
            client_socket.close()
            break

if __name__ == "__main__":
    iniciar_cliente()
