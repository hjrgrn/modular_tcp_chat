import os
import socket

from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes
import rsa
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

from lib.strategies.handlers import EncryptionHandler


class SymAsymEncHandCL(EncryptionHandler):
    """# `SymAsymEncHandCL`
    Concrete implementation of `EncryptionHandler`, uses RSA algorithm to exchange
    a AES key that will be used for the rest of the communication.
    Client side implementation.
    """

    def __init__(self):
        super().__init__()

    def exchange(self, client_sock: socket.socket) -> bytes | Exception:
        # IDEA: two different aes keys for encryption/decryption

        # receive public rsa key
        packet = b""
        pack_len = 251
        total_received = 0
        while total_received < pack_len:
            received = client_sock.recv(512)
            total_received = total_received + len(received)
            packet = packet + received
        pub_rsa_key_bytes = packet[:pack_len]
        # the overflow will never happen
        overflow = packet[pack_len:]
        pub_rsa_key = rsa.PublicKey.load_pkcs1(pub_rsa_key_bytes, format="PEM")

        # generate aes key and cipher
        salt = get_random_bytes(32)
        pass_phrase = os.urandom(12).hex()
        aes_key = PBKDF2(pass_phrase, salt, dkLen=32)
        self.encryption_cipher = AES.new(aes_key, AES.MODE_CBC)
        self.decryption_cipher = AES.new(
            aes_key, AES.MODE_CBC, iv=self.encryption_cipher.iv
        )

        # create packet aes key + initial vector
        packet = aes_key + self.encryption_cipher.iv
        # encrypt packet
        packet = rsa.encrypt(packet, pub_rsa_key)

        # send packet
        pack_len = len(packet)
        total_sent = 0
        while total_sent < pack_len:
            sent = client_sock.send(packet[total_sent:])
            total_sent = total_sent + sent

        # return overflow, there will be no overflow
        return overflow

    def encrypt(self, pack: bytes) -> bytes | Exception:
        encrypted = self.encryption_cipher.encrypt(pad(pack, AES.block_size))
        return encrypted

    def decrypt(self, pack: bytes) -> bytes | Exception:
        decrypted = unpad(self.decryption_cipher.decrypt(pack), AES.block_size)
        return decrypted

    def get_packet_size(self, packet_size: int):
        diff = 16 - (packet_size % 16)
        return packet_size + diff

    @staticmethod
    def get_id():
        return 1
