import socket
from Crypto import Random
from Crypto.PublicKey import RSA
from CryptoClass import AESCrypt, RSACrypt


def generate_RSA_key_pair():
    iv = Random.new().read              #iv = Initialization Vector or nonce, one key for one session rgdless of data
    key = RSA.generate(2048, iv)    
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def client_program(cl_priv_key, cl_pub_key):
    client_socket = socket.socket()
    client_socket.connect(('localhost', 4444))
    client_socket.send(cl_pub_key)      #send public key to server

    encrypted_session_key = client_socket.recv(256) #receive encrypted session key from server 
    print(encrypted_session_key)
    rsa = RSACrypt(cl_priv_key)         #Creating an RSA object to decrypt session key
    session_key = rsa.decrypt_sesskey(encrypted_session_key)
    aes = AESCrypt(session_key)         #Creating an AES object to encrypt/decrypt message

    try:
        message = input("Say Hello to Server -> ")

        while message.lower().strip() != 'exit':
            en_msg = aes.encrypt(message)
            client_socket.send(en_msg)
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break
            decrypted_message = aes.decrypt(encrypted_message)
            print("Server: " + decrypted_message)
            message = input("Client -> ")
    except ValueError:
        print("Server -> Invalid message cannot be sent. Only alphanumeric characters and .,!? are allowed.")
        pass
    except KeyboardInterrupt:
        pass
    
    client_socket.close()

if __name__ == "__main__":
    priv_key, pub_key = generate_RSA_key_pair()
    client_program(priv_key, pub_key)