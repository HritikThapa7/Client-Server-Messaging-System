import unittest
from CryptoClass import AESCrypt, RSACrypt
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from client import *
from server import *

#Test case to check if server is sanitizing message from client correctly
class TestMessageSanitization(unittest.TestCase):

    def test_valid_message(self):
        self.assertTrue(message_sanitization("hello world"))
        self.assertTrue(message_sanitization("hello-world"))
        self.assertTrue(message_sanitization("hello_world"))

    def test_invalid_message(self):
        self.assertFalse(message_sanitization("hello world!"))
        self.assertFalse(message_sanitization("hello world$"))
        self.assertFalse(message_sanitization("hello world#"))

#Test case to check if RSA key pair is being generated correctly
class TestRSAKeyPairGeneration(unittest.TestCase):
    def test_RSA_key_pair_generation(self):
        priv_key, pub_key = generate_RSA_key_pair()
        self.assertTrue(isinstance(RSA.import_key(priv_key), RSA.RsaKey))
        self.assertTrue(isinstance(RSA.import_key(pub_key), RSA.RsaKey))

#Test case to check if AES session key is being generated correctly
class TestAESSessionKeyGeneration(unittest.TestCase):
    def test_AES_session_key_generation(self):
        aes_key = Random.new().read(AES.block_size)
        self.assertIsNotNone(aes_key)

#Test case to check if RSA encryption and decryption of session key is being done correctly
class TestRSAEncryptionDecryptionSessionKey(unittest.TestCase):
    def test_RSA_encryption_decryption_session_key(self):
        priv_key, pub_key = generate_RSA_key_pair()   
        aes_key = Random.new().read(AES.block_size)
        rsa = RSACrypt(pub_key)
        enc_session_key = rsa.encrypt_sesskey(aes_key)
        rsa1 = RSACrypt(priv_key)
        dec_session_key = rsa1.decrypt_sesskey(enc_session_key)
        self.assertEqual(aes_key, dec_session_key)

#Test case to check if AES encryption and decryption of message is being done correctly
class TestAESEncryptionDecryptionMessage(unittest.TestCase):
    def test_AES_encryption_decryption_message(self):
        aes_key = Random.new().read(AES.block_size)
        aes = AESCrypt(aes_key)
        message = "Test message for encryption and decryption"
        enc_message = aes.encrypt(message)
        dec_message = aes.decrypt(enc_message)
        self.assertEqual(message, dec_message)

if __name__ == '__main__':
    unittest.main()

