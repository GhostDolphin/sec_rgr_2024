import socket
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 12345))

    # Відправка клієнтського "привіт"
    client_hello = os.urandom(16).hex()
    client_socket.sendall(client_hello.encode())
    print(f"[CLIENT] Sent: {client_hello}")

    # Прийом "привіт сервера" і публічного ключа
    server_hello = client_socket.recv(1024).decode()
    print(f"[CLIENT] Received: {server_hello}")
    public_key_pem = client_socket.recv(1024)

    # Завантаження публічного ключа
    public_key = serialization.load_pem_public_key(public_key_pem)

    # Генерація premaster і його шифрування
    premaster = os.urandom(16)
    encrypted_premaster = public_key.encrypt(
        premaster,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    client_socket.sendall(encrypted_premaster)
    print(f"[CLIENT] Sent encrypted premaster: {encrypted_premaster.hex()}")

    # Генерація сеансового ключа
    session_key = hashes.Hash(hashes.SHA256())
    session_key.update(client_hello.encode() + server_hello.encode() + premaster)
    session_key = session_key.finalize()
    print(f"[CLIENT] Session key generated: {session_key.hex()}")

    # Відправка зашифрованого повідомлення
    cipher = Cipher(algorithms.AES(session_key[:16]), modes.ECB())
    encryptor = cipher.encryptor()

    # Додавання вирівнювання
    padder = PKCS7(128).padder()
    padded_data = padder.update(b"Hello, Server!") + padder.finalize()

    ready_message = encryptor.update(padded_data) + encryptor.finalize()
    client_socket.sendall(ready_message)
    print(f"[CLIENT] Sent encrypted message: {ready_message.hex()}")

    client_socket.close()

if __name__ == "__main__":
    start_client()
