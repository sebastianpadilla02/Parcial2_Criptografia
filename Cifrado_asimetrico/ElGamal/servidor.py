import socket
from funciones import ElGamal
from parametros import Parametros
import json

criptosistema = None  # Define key as None
client_public_key = None  # Clave pública del cliente

def manejar_cliente(client_socket):
    global criptosistema, client_public_key

    try:
        while True:
            # Recibir mensaje cifrado del cliente
            data = client_socket.recv(2048)
            if not data:
                break

            # Desencriptar el mensaje (NO decodificar como UTF-8 todavía)
            desencriptar = criptosistema.DEG(data)
            
            try:
                # Solo decodifica si el mensaje desencriptado es texto
                mensaje_texto = desencriptar.decode('utf-8')
                print(f"Cliente: {mensaje_texto}")
            except Exception as e:
                print(f"Error al decodificar el mensaje desencriptado {e}")

            # Enviar respuesta al cliente
            response = input("Servidor: ")

            # Cifrar la respuesta usando la clave pública del cliente
            encriptar = criptosistema.EEG(response.encode('utf-8'))
            
            # Enviar el mensaje encriptado al cliente
            client_socket.send(encriptar)
    except Exception as e:
        print(f"Error en enviar/recibir mensajes: {e}")
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

    Parametros(1024)
    criptosistema = ElGamal('parametros.json')

    with open('parametros.json', 'r') as f:
        data = json.load(f)

    # Convertir el JSON en bytes
    json_data = json.dumps(data).encode('utf-8')

    # Enviar el archivo JSON
    client_socket.send(json_data)

    public_key, private_key = criptosistema.GEG()

    # print(f"Enviando pk al cliente: {public_key}")
    client_socket.send(public_key.to_bytes((public_key.bit_length() + 7) // 8, 'big'))

    # Recibir la clave pública del cliente
    client_public_key_bytes = client_socket.recv(2048)
    client_public_key = int.from_bytes(client_public_key_bytes, 'big')
    # print(f'pk recibida del cliente; {client_public_key}')

    criptosistema.public_key = client_public_key

    # print(f'pk final: {criptosistema.public_key}')

    manejar_cliente(client_socket)
    server_socket.close()

if __name__ == "__main__":
    iniciar_servidor()