import socket
import threading
from funciones import RSA_OAEP

criptosistema = None  # Define key as None

def recibir_mensajes(client_socket):
    global criptosistema
    try:
        while True:
            # Recibir el mensaje del servidor
            data = client_socket.recv(1024)
            if not data:
                break

            # Desencriptar el mensaje con la clave privada del cliente
            desencriptado = criptosistema.desencriptar(data)

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
    global criptosistema  # Hacer referencia a la variable global key
    
    # Crear un socket para el cliente
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 8080))

    # Generar par de claves RSA para el cliente
    criptosistema = RSA_OAEP()
    public_key_cliente = criptosistema.public_key
    private_key = criptosistema.private_key

    # Recibir la clave pública del servidor
    public_key_bytes = client_socket.recv(1024)
    public_key = criptosistema.importar(public_key_bytes)
    # criptosistema.public_key = public_key  # Actualizar la clave pública del servidor

    print(f'La llave pública recibida del servidor es: {public_key.export_key()}')
    # criptosistema.actualizar()  # Actualizar el cifrador para usar la clave pública del servidor

    # Enviar la clave pública del cliente al servidor
    public_key_cliente_bytes = criptosistema.public_key.export_key()
    client_socket.send(public_key_cliente_bytes)

    criptosistema.public_key = public_key
    criptosistema.actualizar()

    # Hilo para recibir mensajes del servidor
    thread = threading.Thread(target=recibir_mensajes, args=(client_socket,))
    thread.daemon = True  # Asegurar que el hilo se detenga cuando el programa finalice
    thread.start()

    while True:
        # Enviar mensaje al servidor
        try:
            message = input("Cliente: ")
            if message.lower() == 'salir':
                print("Cerrando conexión...")
                client_socket.close()
                break

            # Cifrar el mensaje con la clave pública del servidor
            encriptar = criptosistema.encriptar(message.encode('utf-8'))

            # Enviar el mensaje cifrado
            client_socket.send(encriptar)
        except Exception as e:
            print(f"Error al enviar mensaje: {e}")
            client_socket.close()
            break

if __name__ == "__main__":
    iniciar_cliente()
