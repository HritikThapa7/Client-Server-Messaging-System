import hashlib
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode

def generate_RSA_key_pair():
    iv = Random.new().read              #iv = Initialization Vector or nonce, one key for one session rgdless of data
    key = RSA.generate(2048, iv)    
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

class AESCrypt(object):
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key).digest()

    def encrypt(self, msg):
        msg = self._pad(msg)
        iv = Random.new().read(self.bs)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(msg.encode()))

    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:self.bs]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[self.bs:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) *  chr(self.bs - len(s) % self.bs)   

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


class RSACrypt(object):
    def __init__(self, priv_key, pub_key):
        self.prvkey = priv_key
        self.pubkey = pub_key

    def encrypt_sesskey(self, sess_key):
        cipher = PKCS1_OAEP.new(RSA.import_key(self.pubkey))
        encrypted_sess_key = cipher.encrypt(sess_key)
        return encrypted_sess_key

    def decrypt_sesskey(self, en_sess_key):
        cipher = PKCS1_OAEP.new(RSA.import_key(self.prvkey))
        decrypted_sess_key = cipher.decrypt(en_sess_key)
        return decrypted_sess_key
        


# if __name__ == "__main__":
#     aes_key = Random.new().read(AES.block_size)
    # aes = AESCrypt(aes_key)
    # msg = "Hello my name is ;!"
    # ciphertext = aes.encrypt(msg)
    # print("Original message:", msg)
    # print("Encrypted message:", ciphertext)
    # decryptMessage = aes.decrypt(ciphertext)
    # print("Decrypted message:", decryptMessage)
    # private_key, public_key = generate_RSA_key_pair()
    # rsa = RSACrypt(private_key, public_key)
    # print("Original key:", aes_key)
    # encrypted_session_key = rsa.encrypt_sesskey(aes_key)
    # print("Encrypted key:", encrypted_session_key)
    # print("Decrypted key:", rsa.decrypt_sesskey(encrypted_session_key))
