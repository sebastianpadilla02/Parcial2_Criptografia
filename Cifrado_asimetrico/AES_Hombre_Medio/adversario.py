import socket
from funciones import Diffie_Hellman, Crypto_functions

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
    dh_adversario = Diffie_Hellman()

    # 2. Interceptar y reemplazar las claves públicas

    # Recibir U de Alice
    U_bytes = alice_socket.recv(1024)
    print(f"Interceptado U de Alice: {U_bytes}")

    # Convertir U a objeto clave pública
    U_alice = dh_adversario.convert_bytes_to_key(U_bytes)

    # Generar la clave pública del adversario (U')
    U_prime = dh_adversario.U
    U_prime_bytes = dh_adversario.public_key_to_bytes()

    # Enviar U' a Bob
    print(f"Enviando U' a Bob: {U_prime_bytes}")
    client_socket.send(U_prime_bytes)

    # Recibir V de Bob
    V_bytes = client_socket.recv(1024)
    print(f"Interceptado V de Bob: {V_bytes}")

    # Convertir V a objeto clave pública
    V_bob = dh_adversario.convert_bytes_to_key(V_bytes)

    # Generar la clave pública del adversario (V')
    V_prime = dh_adversario.U
    V_prime_bytes = dh_adversario.public_key_to_bytes()

    # Enviar V' a Alice
    print(f"Enviando V' a Alice: {V_prime_bytes}")
    alice_socket.send(V_prime_bytes)

    # 3. Calcular los secretos compartidos con Alice y Bob

    # Clave compartida con Alice (W' = alpha * V')
    shared_key_with_alice = dh_adversario.generate_shared_secret(V_bob)
    print(f"Clave compartida con Alice (W'): {shared_key_with_alice}")

    # Clave compartida con Bob (W = beta * U')
    shared_key_with_bob = dh_adversario.generate_shared_secret(U_alice)
    print(f"Clave compartida con Bob (W): {shared_key_with_bob}")

    # Derivar claves simétricas a partir de los secretos compartidos
    key_with_alice = Crypto_functions.KDF(shared_key_with_alice)
    key_with_bob = Crypto_functions.KDF(shared_key_with_bob)

    print(f"Clave simétrica con Alice: {key_with_alice}")
    print(f"Clave simétrica con Bob: {key_with_bob}")

    # Ahora, el adversario tiene claves simétricas con Alice y Bob y puede interceptar y modificar mensajes
    while True:
        # Interceptar mensajes de Alice
        data_from_alice = alice_socket.recv(1024)
        if not data_from_alice:
            break

        # Enviar el mensaje de Alice a Bob (puedes modificar el mensaje aquí si lo deseas)
        client_socket.send(data_from_alice)

        # Interceptar mensajes de Bob
        data_from_bob = client_socket.recv(1024)
        if not data_from_bob:
            break

        # Enviar el mensaje de Bob a Alice (puedes modificar el mensaje aquí si lo deseas)
        alice_socket.send(data_from_bob)

    client_socket.close()
    alice_socket.close()

if __name__ == "__main__":
    adversario()
