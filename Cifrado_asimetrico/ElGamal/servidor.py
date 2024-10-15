import socket
from funciones import ElGamal

criptosistema = None  # Define key as None
client_public_key = None  # Clave pública del cliente

def manejar_cliente(client_socket):
    global criptosistema, client_public_key

    try:
        while True:
            # Recibir mensaje cifrado del cliente
            data = client_socket.recv(1024)
            if not data:
                break

            # Desencriptar el mensaje usando la clave privada del servidor
            desencriptar = criptosistema.DEG(data)
            print(f"Cliente: {desencriptar.decode('utf-8')}")

            # Enviar respuesta al cliente
            response = input("Servidor: ")

            # Cifrar la respuesta usando la clave pública del cliente
            encriptar = criptosistema.EEG(response.encode('utf-8'))

            # Enviar el mensaje encriptado al cliente
            client_socket.send(encriptar)
    except Exception as e:
        print(f"Error en enviar_recibir_mensajes: {e}")
    finally:
        client_socket.close()

def iniciar_servidor():
    global criptosistema, client_public_key

    # Crear un socket para el servidor
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 8080))
    server_socket.listen(1)
    print("Esperando conexión...")

    # Aceptar la conexión del cliente
    client_socket, client_address = server_socket.accept()
    print(f"Conectado con {client_address}")

    # Generar el criptosistema y el par de llaves para el servidor
    criptosistema = ElGamal(227, 113, 12)  # Ajusta los valores de p, q, g según corresponda
    public_key, private_key = criptosistema.GEG()

    print(f"Enviando pk al cliente: {public_key}")
    client_socket.send(public_key.to_bytes((public_key.bit_length() + 7) // 8, 'big'))

    # Recibir la clave pública del cliente
    client_public_key_bytes = client_socket.recv(1024)
    client_public_key = int.from_bytes(client_public_key_bytes, 'big')
    print(f'pk recibida del cliente; {client_public_key}')

    criptosistema.public_key = client_public_key

    manejar_cliente(client_socket)
    server_socket.close()

if __name__ == "__main__":
    iniciar_servidor()
