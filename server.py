import socket
import threading
import hashlib
import os
import time
from Crypto.Util import number
from Crypto.Random import random

clients = []
user_data = {}  # username -> (salt, hash, pin, certificate)
certificates = {}  # username -> certificate
client_certificates = {}  # client_socket -> certificate
client_usernames = {}  # client_socket -> username

lock = threading.Lock()

def hash_password(password, salt=None):
    if not salt:
        salt = os.urandom(16)
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt, hash_obj

def diffie_hellman_key_exchange():
    p = number.getPrime(512)
    g = number.getPrime(512)
    private_key = random.StrongRandom().randint(1, p - 1)
    public_key = pow(g, private_key, p)
    return p, g, private_key, public_key

def handle_client(client_socket, address):
    global clients
    try:
        client_socket.send("Welcome to the Secure Broadcast Server!\n".encode())
        client_socket.send("1. Sign Up\n2. Log In\nChoose an option: ".encode())
        option = client_socket.recv(1024).decode().strip()
        
        if option == '1':
            sign_up(client_socket)
        elif option == '2':
            if not log_in(client_socket):
                return
        
        # Diffie-Hellman key exchange
        p, g, server_private_key, server_public_key = diffie_hellman_key_exchange()
        client_socket.send(f"{p} {g} {server_public_key}".encode())
        client_public_key = int(client_socket.recv(1024).decode())
        shared_secret = pow(client_public_key, server_private_key, p)

        client_username = client_usernames.get(client_socket)
        if client_username:
            client_socket.send(f"Shared secret established. You can start messaging.\n".encode())

            while True:
                message = client_socket.recv(1024).decode().strip()
                if message:
                    broadcast(f"{client_username} ({time.strftime('%Y-%m-%d %H:%M:%S')}): {message}", client_socket)
                else:
                    remove_client(client_socket)
                    break

    except Exception as e:
        print(f"Error: {e}")
        remove_client(client_socket)

def sign_up(client_socket):
    client_socket.send("Enter username: ".encode())
    username = client_socket.recv(1024).decode().strip()
    
    client_socket.send("Enter password (minimum 8 characters): ".encode())
    password = client_socket.recv(1024).decode().strip()

    if len(password) < 8:
        client_socket.send("Password too short. Try again.\n".encode())
        return
    
    client_socket.send("Enter 4-digit PIN: ".encode())
    pin = client_socket.recv(1024).decode().strip()

    if len(pin) != 4 or not pin.isdigit():
        client_socket.send("Invalid PIN. Try again.\n".encode())
        return
    
    salt, hashed_pw = hash_password(password)
    certificate = os.urandom(16).hex()
    
    with lock:
        user_data[username] = (salt, hashed_pw, pin, certificate)
        certificates[username] = certificate

    client_socket.send(f"Sign up successful. Your certificate is {certificate}\n".encode())

def log_in(client_socket):
    client_socket.send("Enter username: ".encode())
    username = client_socket.recv(1024).decode().strip()

    if username not in user_data:
        client_socket.send("Username not found. Try again.\n".encode())
        return False
    
    attempts = 0
    while attempts < 3:
        client_socket.send("Enter password: ".encode())
        password = client_socket.recv(1024).decode().strip()
        
        salt, stored_hash, pin, certificate = user_data[username]
        _, hashed_pw = hash_password(password, salt)
        
        if hashed_pw == stored_hash:
            client_socket.send(f"Login successful. Your certificate is {certificate}\n".encode())
            with lock:
                client_certificates[client_socket] = certificate
                client_usernames[client_socket] = username
            return True
        else:
            attempts += 1
            client_socket.send(f"Incorrect password. {3 - attempts} attempts left.\n".encode())
    
    client_socket.send("Too many failed attempts. Please try again later.\n".encode())
    time.sleep(600)  # 10 minutes
    return False

def broadcast(message, connection):
    for client in clients:
        if client != connection:
            try:
                client.send(message.encode())
            except:
                remove_client(client)

def remove_client(client_socket):
    if client_socket in clients:
        clients.remove(client_socket)
        if client_socket in client_certificates:
            del client_certificates[client_socket]
        if client_socket in client_usernames:
            del client_usernames[client_socket]

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 5555))
    server.listen(5)
    print("Server started and listening on port 5555...")
    
    while True:
        client_socket, addr = server.accept()
        with lock:
            clients.append(client_socket)
        print(f"New connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_handler.start()

if __name__ == "__main__":
    start_server()
