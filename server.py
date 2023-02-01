import socket
from CryptoClass import AESCrypt, RSACrypt
from Crypto import Random
from Crypto.Cipher import AES

def server_program():
    server_socket = socket.socket()
    server_socket.bind(('localhost', 4444))
    server_socket.listen(1)
    conn, address = server_socket.accept()

    print("Connection from:" + str(address))

    public_key = conn.recv(2048)                    #receiving public key from client
    
    aes_key = Random.new().read(AES.block_size)     #generating an aes key or a session key
    aes = AESCrypt(aes_key)                         #creating an AES object with aes key for message encryption

    rsa = RSACrypt(public_key)                      #creating an RSA object with Public key of client
    enc_session_key = rsa.encrypt_sesskey(aes_key)              #encrypting session key with public key of client
    conn.send(enc_session_key)

    while True:
        encrypted_message = conn.recv(4096)         #receiving encrypted msg from client
        if not encrypted_message:
            break
        decrypted_message = aes.decrypt(encrypted_message)
        print("Client: "+str(decrypted_message))
        data = input("Server -> ")
        en_msg = aes.encrypt(data)
        conn.send(en_msg)
    conn.close()

if __name__ == "__main__":
    server_program()