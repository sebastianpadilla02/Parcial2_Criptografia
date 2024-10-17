import socket
import threading
from funciones import ElGamal

criptosistema = None  # Define key as None

def recibir_mensajes(client_socket):
    global criptosistema
    try:
        while True:
            # Recibir el mensaje cifrado del servidor
            data = client_socket.recv(2048)
            if not data:
                break

            # Desencriptar el mensaje (NO decodificar como UTF-8 todavía)
            desencriptado = criptosistema.DEG(data)
            
            try:
                # Solo decodifica si el mensaje desencriptado es texto
                mensaje_texto = desencriptado.decode('utf-8')
                print(f"\rServidor: {mensaje_texto}")
            except Exception as e:
                print(f"Error al decodificar el mensaje desencriptado, no es texto UTF-8 válido: {desencriptado}")

            print("Cliente: ", end="", flush=True)
    except Exception as e:
        print(f"Error en recibir mensajes: {e}")
    finally:
        client_socket.close()



def iniciar_cliente():
    global criptosistema  # Hacer referencia a la variable global key
    
    # Crear un socket para el cliente
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 8080))

    # Generar par de claves ElGamal para el cliente
    criptosistema = ElGamal('parametros.json')
    public_key, private_key = criptosistema.GEG()

    # Recibir la clave pública del servidor
    server_public_key_bytes = client_socket.recv(2048)
    server_public_key = int.from_bytes(server_public_key_bytes, 'big')
    # print(f'server_public_key: {server_public_key}')

    # Enviar la clave pública del cliente al servidor
    # print(f"Enviando pk al servidor: {public_key}")
    client_socket.send(public_key.to_bytes((public_key.bit_length() + 7) // 8, 'big'))

    criptosistema.public_key = server_public_key

    # print(f'nueva public:{criptosistema.public_key}')

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
            encriptar = criptosistema.EEG(message.encode('utf-8'))
            # print(encriptar)

            # Enviar el mensaje cifrado
            client_socket.send(encriptar)
        except Exception as e:
            print(f"Error al enviar mensaje: {e}")
            client_socket.close()
            break


if __name__ == "__main__":
    iniciar_cliente()

