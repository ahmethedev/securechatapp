import socket
import threading
import hashlib
from Crypto.Util import number
from Crypto.Random import random

def diffie_hellman_key_exchange(client_socket):
    params = client_socket.recv(1024).decode().split()
    p = int(params[0])
    g = int(params[1])
    server_public_key = int(params[2])
    
    private_key = random.StrongRandom().randint(1, p - 1)
    public_key = pow(g, private_key, p)
    
    client_socket.send(str(public_key).encode())
    shared_secret = pow(server_public_key, private_key, p)
    return shared_secret

def receive_messages(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if message:
                print(message)
            else:
                break
        except:
            break

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 5555))
    
    print(client_socket.recv(1024).decode())
    option = input()
    client_socket.send(option.encode())
    
    while True:
        response = client_socket.recv(1024).decode()
        print(response)
        if "successful" in response or "too short" in response or "Invalid" in response:
            break
        client_socket.send(input().encode())
    
    if "certificate" in response:
        shared_secret = diffie_hellman_key_exchange(client_socket)
        print("Shared secret established. You can start messaging.")
        
        threading.Thread(target=receive_messages, args=(client_socket,)).start()
        
        while True:
            message = input()
            if message:
                client_socket.send(message.encode())

if __name__ == "__main__":
    start_client()
