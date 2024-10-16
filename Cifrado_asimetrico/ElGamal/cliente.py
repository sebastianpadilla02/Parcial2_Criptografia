import socket
import threading
from funciones import ElGamal

criptosistema = None  # Define key as None

def recibir_mensajes(client_socket):
    global criptosistema
    try:
        while True:
            # Recibir el mensaje del servidor
            data = client_socket.recv(2048)
            if not data:
                break

            # print(data)
            # Desencriptar el mensaje con la clave privada del cliente
            desencriptado = criptosistema.DEG(data)

            # Mostrar el mensaje descifrado
            print(f"\rServidor: {desencriptado.decode('utf-8')}")
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
    criptosistema = ElGamal(p = 137264501074495181280555132673901931323332164724815133317526595627537522562067022989603699054588480389773079016561323343477054349336451609284971148159280724829128531552270321268457769520042856144429883077983691811201653430137376919960068969990507421437958462547891425943025305810160065324145921753228735283903,
        q = 68632250537247590640277566336950965661666082362407566658763297813768761281033511494801849527294240194886539508280661671738527174668225804642485574079640362414564265776135160634228884760021428072214941538991845905600826715068688459980034484995253710718979231273945712971512652905080032662072960876614367641951,
        g = 40746562294764965373407784234554073062674073565341303353016758609344799210654104763969824808430330931109448281620048720300276969942539907157417365502013807736680793541720602226570436490901677489617911977499169334249484471027700239163555304280499401445437347279647322836086848012965178946904650279473615383579)

    public_key, private_key = criptosistema.GEG()

    # Recibir la clave pública del servidor
    server_public_key_bytes = client_socket.recv(2048)
    server_public_key = int.from_bytes(server_public_key_bytes, 'big')
    # print(f'pk recibida del servidor: {server_public_key}')

    # Enviar la clave pública del cliente al servidor
    # print(f"Enviando pk al servidor: {public_key}")
    client_socket.send(public_key.to_bytes((public_key.bit_length() + 7) // 8, 'big'))

    criptosistema.public_key = server_public_key

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
