import socket
import threading

from funciones import Crypto_functions, Diffie_Hellman

key = None  # Define key as None

# Función para manejar al cliente
def manejar_cliente(client_socket):
    global key

    try:
        while True:
            # Recibir mensaje del cliente
            data = client_socket.recv(1024)
            if not data:
                break

            # Extraer el nonce(iv) del mensaje
            iv = data[:16]  # Asumimos que el nonce(iv) es de 16 bytes en AES-256
            encrypted_message = data[16:] # El mensaje encriptado

            # Desencriptar el mensaje
            desencriptar = Crypto_functions.AES_CBC_decrypt(key, iv, encrypted_message)
            # Imprimir el mensaje del cliente
            print(f"Cliente: {desencriptar.decode('utf-8')}")
            
            # Enviar respuesta al cliente
            response = input("Servidor: ")

            # Generar un nuevo nonce(iv) para la respuesta
            iv = Crypto_functions.generar_iv_AES()
            # Encriptar la respuesta
            encriptar = Crypto_functions.AES_CBC_encrypt(key, iv, response.encode('utf-8'))

            # Enviar el iv y el mensaje encriptado
            client_socket.send(iv + encriptar)
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

    #Iniciar Diffie_hellman
    key_change = Diffie_Hellman()

    U = key_change.U

    U_bytes = key_change.public_key_to_bytes()
    print(f"Enviando u al cliente: {U_bytes}")

    client_socket.send(U_bytes)

    # Esperar el valor V del cliente
    V_bytes = client_socket.recv(1024)
    print(f"Recibido V del cliente: {V_bytes}")

    V = key_change.convert_bytes_to_key(V_bytes)

    # 6. Calcular el secreto compartido W = alpha * V (clave pública de Bob)
    W = key_change.generate_shared_secret(V)
    print(f"Clave compartida generada: {W}")

    key = Crypto_functions.KDF(W)
    print(f"Llave definitiva: {key}")

    # # Guardar la clave en un archivo binario
    # with open('key.bin', 'wb') as file:
    #     file.write(key)

    manejar_cliente(client_socket)
    server_socket.close()
    print("server_socket cerrado")

if __name__ == "__main__":
    iniciar_servidor()