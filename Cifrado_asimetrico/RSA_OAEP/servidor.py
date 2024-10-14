import socket
from funciones import RSA_OAEP

criptosistema = None  # Define key as None

def manejar_cliente(client_socket):
    global criptosistema

    try:
        while True:
            # Recibir mensaje cifrado del cliente
            data = client_socket.recv(1024)
            if not data:
                break

            # Desencriptar el mensaje usando la clave privada del servidor
            desencriptar = criptosistema.desencriptar(data)
            print(f"Cliente: {desencriptar.decode('utf-8')}")

            # Enviar respuesta al cliente
            response = input("Servidor: ")

            # Cifrar la respuesta usando la clave pública del cliente
            encriptar = criptosistema.encriptar(response.encode('utf-8'))

            # Enviar el mensaje encriptado
            client_socket.send(encriptar)
    except Exception as e:
        print(f"Error en enviar_recibir_mensajes: {e}")
    finally:
        client_socket.close()

def iniciar_servidor():
    global criptosistema

    # Crear un socket para el servidor
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 8080))
    server_socket.listen(1)
    print("Esperando conexión...")

    # Aceptar la conexión del cliente
    client_socket, client_address = server_socket.accept()
    print(f"Conectado con {client_address}")

    # Generar par de claves RSA para el servidor
    criptosistema = RSA_OAEP()
    public_key = criptosistema.public_key
    private_key = criptosistema.private_key

    # Enviar la clave pública del servidor al cliente
    public_key_bytes = public_key.export_key()
    print(f'La llave publica enviada es: {public_key_bytes}')
    client_socket.send(public_key_bytes)

    criptosistema.actualizar()
    manejar_cliente(client_socket)
    server_socket.close()

if __name__ == "__main__":
    iniciar_servidor()
