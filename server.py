import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

# Генерація RSA ключів
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Зберігаємо сеансовий ключ
session_key = None

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", 12345))
    server_socket.listen(1)

    print("[SERVER] Waiting for connection...")
    conn, addr = server_socket.accept()
    print(f"[SERVER] Connected to {addr}")

    # Прийом клієнтського "привіт"
    client_hello = conn.recv(1024).decode()
    print(f"[SERVER] Received: {client_hello}")

    # Відправка "привіт сервера" і публічного ключа
    server_hello = os.urandom(16).hex()
    conn.sendall(server_hello.encode())
    conn.sendall(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    print("[SERVER] Sent server hello and public key")

    # Прийом зашифрованого premaster
    encrypted_premaster = conn.recv(256)
    premaster = private_key.decrypt(
        encrypted_premaster,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"[SERVER] Premaster decrypted: {premaster.hex()}")

    # Генерація сеансового ключа
    global session_key
    session_key = hashes.Hash(hashes.SHA256())
    session_key.update(client_hello.encode() + server_hello.encode() + premaster)
    session_key = session_key.finalize()
    print(f"[SERVER] Session key generated: {session_key.hex()}")

    # Прийом зашифрованого повідомлення
    ready_message = conn.recv(1024)
    print(f"[SERVER] Received encrypted: {ready_message}")

    # Дешифрування повідомлення
    cipher = Cipher(algorithms.AES(session_key[:16]), modes.ECB())
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(ready_message) + decryptor.finalize()

    # Видалення вирівнювання
    unpadder = PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    print(f"[SERVER] Decrypted message: {decrypted_message.decode()}")

    conn.close()

if __name__ == "__main__":
    start_server()
