from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import socket

def load_public_key():
    with open("public_key.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())

def verify_signature(public_key, signature, message):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 9999))
server_socket.listen(1)
print("Server is listening...")

public_key = load_public_key()

connection, _ = server_socket.accept()
with connection:
    received_data = connection.recv(1024)
    message, signature = received_data[:-256], received_data[-256:]
    if verify_signature(public_key, signature, message):
        print("Signature is valid.")
        print("Received message:", message.decode())
    else:
        print("Signature is invalid.")

server_socket.close()
