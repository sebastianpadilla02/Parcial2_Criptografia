import socket
from funciones import Diffie_Hellman, Crypto_functions

def desencriptado_AES(data, key, nombre):
    try:
        # Extraer el nonce(iv) del mensaje
        iv = data[:16]  # Asumimos que el nonce(iv) es de 16 bytes (para AES)
        encrypted_message = data[16:] # El mensaje encriptado

        # Desencriptar el mensaje
        desencriptado = Crypto_functions.AES_CBC_decrypt(key, iv, encrypted_message)

        # Mostrar el mensaje desencriptado
        return desencriptado.decode('utf-8')
    except Exception as e:
        print(f"Error al desencriptar el mensaje de {nombre}: {e}")

# El adversario actúa como un intermediario entre Servidor y Cliente
def adversario():

    # 1. Crear dos conexiones de socket
    # Conexión a Servidor
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect(('127.0.0.1', 8080))  # IP de Servidor

    # Conexión a Cliente
    bob_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob_socket.bind(('127.0.0.1', 8081))  # El adversario actuará como "servidor" para el Cliente
    bob_socket.listen(1)
    print("Esperando conexión de Cliente...")

    client_socket, client_address = bob_socket.accept()
    print(f"Conectado con Cliente en {client_address}")

    # Inicializar Diffie-Hellman del adversario
    dh_adversario_servidor = Diffie_Hellman()
    dh_adversario_cliente = Diffie_Hellman()

    # 2. Interceptar y reemplazar las claves públicas

    # Recibir U del Servidor
    U_bytes = server_socket.recv(1024)
    # print(f"Interceptado U de Servidor: {U_bytes}")

    # Convertir U a objeto clave pública
    U = dh_adversario_servidor.convert_bytes_to_key(U_bytes)

    # Calcular V' y enviar a Servidor
    V_prime = dh_adversario_servidor.public_key_to_bytes()
    # print(f"Enviando V al servidor: {V_prime}")
    server_socket.send(V_prime)

    # Generar la clave pública del adversario (U')
    U_prime = dh_adversario_cliente.U
    U_prime_bytes = dh_adversario_cliente.public_key_to_bytes()

    # Enviar U' a Cliente
    # print(f"Enviando U' a Cliente: {U_prime_bytes}")
    client_socket.send(U_prime_bytes)

    # Recibir V de Cliente
    V_bytes = client_socket.recv(1024)
    # print(f"Interceptado V de Bob: {V_bytes}")

    # Convertir V a objeto clave pública
    V = dh_adversario_cliente.convert_bytes_to_key(V_bytes)

    # 3. Calcular los secretos compartidos con el Cliente y el Servidor

    # Clave compartida con Servidor (W' = alpha * V')
    shared_key_with_alice = dh_adversario_servidor.generate_shared_secret(U)
    # print(f"Clave compartida con Servidor (W'): {shared_key_with_alice}")

    # Clave compartida con Cliente (W = beta * U')
    shared_key_with_bob = dh_adversario_cliente.generate_shared_secret(V)
    # print(f"Clave compartida con Cliente (W): {shared_key_with_bob}")

    # Derivar claves simétricas a partir de los secretos compartidos
    key_with_server = Crypto_functions.KDF(shared_key_with_alice)
    key_with_client = Crypto_functions.KDF(shared_key_with_bob)

    # print(f"Clave simétrica con Servidor: {key_with_server}")
    # print(f"Clave simétrica con Cliente: {key_with_client}")

    # Ahora, el adversario tiene claves simétricas con Servidor y cliente, y puede interceptar y modificar mensajes
    while True:
        # Interceptar mensajes del Cliente
        data_from_client = client_socket.recv(1024)
        if not data_from_client:
            break

        desencriptado = desencriptado_AES(data_from_client, key_with_client, 'Cliente')
        print(f"Cliente: {desencriptado} ", end='\n', flush=True)

        # Opción para modificar el mensaje interceptado o reenviar tal cual
        mensaje_para_server = input("Adversario: Ingresa el mensaje a enviar a Servidor (o presiona Enter para reenviar el mensaje interceptado): ")

        if mensaje_para_server.strip() == "":  # Si no se ingresa un mensaje, se reenvía el original del Cliente
            # Generar un nuevo nonce (IV) para el mensaje modificado
            iv = Crypto_functions.generar_iv_AES()
            # Encriptar el mensaje del adversario
            encriptado = Crypto_functions.AES_CBC_encrypt(key_with_server, iv, desencriptado.encode('utf-8'))
            # Enviar el mensaje a Servidor
            server_socket.send(iv + encriptado)
        else:
            # Generar un nuevo nonce (IV) para el mensaje modificado
            iv = Crypto_functions.generar_iv_AES()
            # Encriptar el mensaje del adversario
            encriptado = Crypto_functions.AES_CBC_encrypt(key_with_server, iv, mensaje_para_server.encode('utf-8'))
            # Enviar el nuevo mensaje modificado a Servidor
            server_socket.send(iv + encriptado)

        # Interceptar mensajes de Servidor
        data_from_server = server_socket.recv(1024)
        if not data_from_server:
            break

        desencriptado2 = desencriptado_AES(data_from_server, key_with_server, 'Servidor')
        print(f"Servidor: {desencriptado2} ", end='\n', flush=True)

        # Opción para modificar el mensaje interceptado o reenviar tal cual
        mensaje_para_client = input("Adversario: Ingresa el mensaje a enviar a Cliente (o presiona Enter para reenviar el mensaje interceptado): ")

        if mensaje_para_client.strip() == "":  # Si no se ingresa un mensaje, se reenvía el original de Servidor
            # Generar un nuevo nonce (IV) para el mensaje modificado
            iv = Crypto_functions.generar_iv_AES()
            # Encriptar el mensaje del adversario
            encriptado = Crypto_functions.AES_CBC_encrypt(key_with_client, iv, desencriptado2.encode('utf-8'))
            # Enviar el nuevo mensaje a Cliente
            client_socket.send(iv + encriptado)
        else:
            # Generar un nuevo nonce (IV) para el mensaje modificado
            iv = Crypto_functions.generar_iv_AES()
            # Encriptar el mensaje del adversario
            encriptado = Crypto_functions.AES_CBC_encrypt(key_with_client, iv, mensaje_para_client.encode('utf-8'))
            # Enviar el nuevo mensaje modificado a Cliente
            client_socket.send(iv + encriptado)

    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    adversario()
