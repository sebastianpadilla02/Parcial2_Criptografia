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

# El adversario actúa como un intermediario entre Alice (servidor) y Bob (cliente)
def adversario():
    # 1. Crear dos conexiones de socket
    # Conexión a Alice (servidor)
    alice_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice_socket.connect(('127.0.0.1', 8080))  # IP de Alice (servidor)

    # Conexión a Bob (cliente)
    bob_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob_socket.bind(('127.0.0.1', 8081))  # El adversario actuará como "servidor" para Bob
    bob_socket.listen(1)
    print("Esperando conexión de Bob...")

    client_socket, client_address = bob_socket.accept()
    print(f"Conectado con Bob en {client_address}")

    # Inicializar Diffie-Hellman del adversario
    dh_adversario_servidor = Diffie_Hellman()
    dh_adversario_cliente = Diffie_Hellman()

    # 2. Interceptar y reemplazar las claves públicas

    # Recibir U de Alice
    U_bytes = alice_socket.recv(1024)
    print(f"Interceptado U de Alice: {U_bytes}")

    # Convertir U a objeto clave pública
    U = dh_adversario_servidor.convert_bytes_to_key(U_bytes)

    #Calcular V' y enviar a servidor(Alice)
    V_prime = dh_adversario_servidor.public_key_to_bytes()
    print(f"Enviando V al servidor: {V_prime}")
    alice_socket.send(V_prime)

    # Generar la clave pública del adversario (U')
    U_prime = dh_adversario_cliente.U
    U_prime_bytes = dh_adversario_cliente.public_key_to_bytes()

    # Enviar U' a Bob
    print(f"Enviando U' a Bob: {U_prime_bytes}")
    client_socket.send(U_prime_bytes)

    # Recibir V de Bob
    V_bytes = client_socket.recv(1024)
    print(f"Interceptado V de Bob: {V_bytes}")

    # Convertir V a objeto clave pública
    V = dh_adversario_cliente.convert_bytes_to_key(V_bytes)

    # 3. Calcular los secretos compartidos con Alice y Bob

    # Clave compartida con Alice (W' = alpha * V')
    shared_key_with_alice = dh_adversario_servidor.generate_shared_secret(U)
    print(f"Clave compartida con Alice (W'): {shared_key_with_alice}")

    # Clave compartida con Bob (W = beta * U')
    shared_key_with_bob = dh_adversario_cliente.generate_shared_secret(V)
    print(f"Clave compartida con Bob (W): {shared_key_with_bob}")

    # Derivar claves simétricas a partir de los secretos compartidos
    key_with_alice = Crypto_functions.KDF(shared_key_with_alice)
    key_with_bob = Crypto_functions.KDF(shared_key_with_bob)

    print(f"Clave simétrica con Alice: {key_with_alice}")
    print(f"Clave simétrica con Bob: {key_with_bob}")

    # Ahora, el adversario tiene claves simétricas con Alice y Bob y puede interceptar y modificar mensajes
    while True:
        # Interceptar mensajes de Bob
        data_from_bob = client_socket.recv(1024)
        if not data_from_bob:
            break

        desencriptado = desencriptado_AES(data_from_bob, key_with_bob, 'Bob')
        print(f"Bob: {desencriptado} ", end='\n', flush=True)

        # Opción para modificar el mensaje interceptado o reenviar tal cual
        mensaje_para_alice = input("\nAdversario: Ingresa el mensaje a enviar a Alice (o presiona Enter para reenviar el mensaje interceptado): ")

        if mensaje_para_alice.strip() == "":  # Si no se ingresa un mensaje, se reenvía el original de Bob
            # Generar un nuevo nonce (IV) para el mensaje modificado
            iv = Crypto_functions.generar_iv_AES()
            # Encriptar el mensaje del adversario
            encriptado = Crypto_functions.AES_CBC_encrypt(key_with_alice, iv, desencriptado.encode('utf-8'))
            # Enviar el nuevo mensaje modificado a Alice
            alice_socket.send(iv + encriptado)
        else:
            # Generar un nuevo nonce (IV) para el mensaje modificado
            iv = Crypto_functions.generar_iv_AES()
            # Encriptar el mensaje del adversario
            encriptado = Crypto_functions.AES_CBC_encrypt(key_with_alice, iv, mensaje_para_alice.encode('utf-8'))
            # Enviar el nuevo mensaje modificado a Alice
            alice_socket.send(iv + encriptado)

        # Interceptar mensajes de Alice
        data_from_alice = alice_socket.recv(1024)
        if not data_from_alice:
            break

        desencriptado2 = desencriptado_AES(data_from_alice, key_with_alice, 'Alice')
        print(f"Alice: {desencriptado2} ", end='\n', flush=True)

        # Opción para modificar el mensaje interceptado o reenviar tal cual
        mensaje_para_bob = input("\nAdversario: Ingresa el mensaje a enviar a Bob (o presiona Enter para reenviar el mensaje interceptado): ")

        if mensaje_para_bob.strip() == "":  # Si no se ingresa un mensaje, se reenvía el original de Alice
            # Generar un nuevo nonce (IV) para el mensaje modificado
            iv = Crypto_functions.generar_iv_AES()
            # Encriptar el mensaje del adversario
            encriptado = Crypto_functions.AES_CBC_encrypt(key_with_bob, iv, desencriptado2.encode('utf-8'))
            # Enviar el nuevo mensaje modificado a Bob
            client_socket.send(iv + encriptado)
        else:
            # Generar un nuevo nonce (IV) para el mensaje modificado
            iv = Crypto_functions.generar_iv_AES()
            # Encriptar el mensaje del adversario
            encriptado = Crypto_functions.AES_CBC_encrypt(key_with_bob, iv, mensaje_para_bob.encode('utf-8'))
            # Enviar el nuevo mensaje modificado a Bob
            client_socket.send(iv + encriptado)

    client_socket.close()
    alice_socket.close()

if __name__ == "__main__":
    adversario()
