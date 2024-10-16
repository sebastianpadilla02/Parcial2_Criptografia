import socket
from funciones import ElGamal

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

            # Desencriptar el mensaje
            # print(data)
            desencriptar = criptosistema.DEG(data)
            print(f"Cliente: {desencriptar.decode('utf-8')}")

            # Enviar respuesta al cliente
            response = input("Servidor: ")

            # Cifrar la respuesta usando la clave pública del cliente
            encriptar = criptosistema.EEG(response.encode('utf-8'))
            # print(encriptar)

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
    criptosistema = ElGamal(p = 137264501074495181280555132673901931323332164724815133317526595627537522562067022989603699054588480389773079016561323343477054349336451609284971148159280724829128531552270321268457769520042856144429883077983691811201653430137376919960068969990507421437958462547891425943025305810160065324145921753228735283903,
			q = 68632250537247590640277566336950965661666082362407566658763297813768761281033511494801849527294240194886539508280661671738527174668225804642485574079640362414564265776135160634228884760021428072214941538991845905600826715068688459980034484995253710718979231273945712971512652905080032662072960876614367641951,
			g = 40746562294764965373407784234554073062674073565341303353016758609344799210654104763969824808430330931109448281620048720300276969942539907157417365502013807736680793541720602226570436490901677489617911977499169334249484471027700239163555304280499401445437347279647322836086848012965178946904650279473615383579)
    
    public_key, private_key = criptosistema.GEG()

    # print(f"Enviando pk al cliente: {public_key}")
    client_socket.send(public_key.to_bytes((public_key.bit_length() + 7) // 8, 'big'))

    # Recibir la clave pública del cliente
    client_public_key_bytes = client_socket.recv(2048)
    client_public_key = int.from_bytes(client_public_key_bytes, 'big')
    # print(f'pk recibida del cliente; {client_public_key}')

    criptosistema.public_key = client_public_key

    manejar_cliente(client_socket)
    server_socket.close()

if __name__ == "__main__":
    iniciar_servidor()
