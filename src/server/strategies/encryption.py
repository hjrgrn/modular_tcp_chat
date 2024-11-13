import logging
import socket

import rsa
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

from lib.constants import HandshakeFailed
from lib.strategies.handlers import EncryptionHandler


class SymAsymEncHandSS(EncryptionHandler):
    """# `SymAsymEncHandSS`
    Concrete implementation of `EncryptionHandler`, uses RSA algorithm to exchange
    a AES session key that will be used for the rest of the communication.
    The same symmetric key is used for encryption and decryption.
    Server side implementation.
    """

    def __init__(self):
        super().__init__()

    def exchange(self, client_sock: socket.socket) -> bytes | Exception:
        # TODO: nonce
        # TODO: seq number
        pub_rsa_key, priv_rsa_key = rsa.newkeys(1024)
        packet = pub_rsa_key.save_pkcs1(format="PEM")
        pack_len = len(packet)
        total_sent = 0
        while total_sent < pack_len:
            bytes_sent = client_sock.send(packet[total_sent:])
            if bytes_sent == 0:
                return HandshakeFailed(
                    "Encrypted handshake failed. Failed to sed public rsa key."
                )
            total_sent = total_sent + bytes_sent

        # receive aes + initial vector packet
        packet = b""
        pack_len = 128
        total_received = 0
        while total_received < pack_len:
            received = client_sock.recv(512)
            if received == b"":
                return HandshakeFailed(
                    "Encrypted handshake failed. Failed to receive aes key and initial vector."
                )
            total_received = total_received + len(received)
            packet = packet + received
        key_encrypted = packet[:pack_len]
        # possible overflow received
        overflow = packet[pack_len:]

        # decrypt packet
        try:
            packet_plain = rsa.decrypt(key_encrypted, priv_rsa_key)
        except rsa.DecryptionError as e:
            return e
        except Exception as e:
            # Unexpected error
            logging.exception(e)
            return e

        aes_key = packet_plain[:32]
        iv = packet_plain[32 : 32 + 16]

        # generate ciphers
        # NOTE: same encryption key is used for encryption and decryption
        self.encryption_cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        self.decryption_cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)

        # return overflow
        return overflow

    @staticmethod
    def get_id():
        return 1

    def encrypt(self, pack: bytes) -> bytes | Exception:
        encrypted = self.encryption_cipher.encrypt(pad(pack, AES.block_size))
        return encrypted

    def decrypt(self, pack: bytes) -> bytes | Exception:
        decrypted = unpad(self.decryption_cipher.decrypt(pack), AES.block_size)
        return decrypted

    def get_packet_size(self, packet_size: int):
        diff = 16 - (packet_size % 16)
        return packet_size + diff
