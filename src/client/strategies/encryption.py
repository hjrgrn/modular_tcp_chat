from getpass import getpass
import hashlib
import os
import random
import socket
import string

from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes
import rsa
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

from lib.constants import (
    DecryptionError,
    EncryptionError,
    EncryptionHandlerFailed,
    HandshakeFailed,
)
from lib.strategies.handlers import EncryptionHandler


class SharedSecretCS(EncryptionHandler):
    """# SharedSecretSS

    ## Description

    Concrete implementation of `EncryptionHandler`.
    This implementation uses an RSA key to exchange a AES key (both specific for every single connection), the last one will be used during the final part of the exchange and during the session.
    During the exchange nonces, sha512 hashes, a shared secret(collected interactively) and a hmac key are used to verify the integrity of the exchange in order to prevent: playback attacks, segment replay attacks, connection replay attack and spoofing(server side and client side); hopefully.
    This implementation offers no protection against disrupting minaces like DOS and truncation attacks at application layer.
    Every message exchanged is encrypted using AES and its integrity is verifyied using the sha256 algorithm, a sequence number(selected pseudo randomly during the exchange) and a hmac key.
    Some procedure are willingly redundant.
    This implementation assures client authentication but not user authentication, which is responsability of `HandshakeClientSide` and `HandshakeServerSide`.


    ## Packet

    ### Decrypted

    sequence number: 4 bytes
    payload: not limited

    ### Encrypted

    encrypted payload: multiple of 16 bytes
    hash: 64 bytes

    ### Notes

    The size of the payload is not limited, the limitation is delegated to `HandshakeServerSide` and `HandshakeClientSide`


    ## Notes

    This is only a toy project made for practice purpose and should not be used into production or relied upon.
    """

    def __init__(self):
        super().__init__()
        self.shared_secret: bytes = None
        self.sequence_number_recv: int = None
        self.sequence_number_send: int = None
        # TODO: make this configurable
        # NOTE: max_seq_num - 1
        self.max_seq_num: int = 4096
        # Length of the string seq num
        self.max_len_seq_num: int = len(str(self.max_seq_num))
        # TODO: make this configurable
        self.nonce_length: int = 64
        self.encryption_cipher = None
        self.decryption_cipher = None
        self.hmac_key: bytes = None
        # TODO: make this configurable
        self.hmac_key_length: int = 64
        # These will be cleaned up after exchange
        self.nonce_recv: bytes | None = None
        self.nonce_sent: bytes | None = None
        self.pub_rsa_key: rsa.PublicKey | None = None
        self.aes_key = None
        self.hash_function = None

    def setup(self) -> None | EncryptionHandlerFailed:
        """# `setup`
        Requires the insertion of a secret that will have to be shared by
        the amministrator of the server in a secure way, without said secret the client won't be
        able to connect.
        """
        self.shared_secret = getpass("Type in your shared secret:").encode("utf-8")

    def clone(self):
        cloned = SharedSecretCS()
        cloned.shared_secret = self.shared_secret
        return cloned

    def exchange(self, client_sock: socket.socket):
        # receive nonce and public rsa key
        error = self._recv_nonce_rsa(client_sock)
        if isinstance(error, Exception):
            return error
        overflow, hash = error

        # send hash
        error = self._send_packet(client_sock, hash)
        if error is not None:
            return HandshakeFailed("Failed to send hash of nonce and public rsa key")

        # send aes key, initial vector, nonce, hmac_key, seq number recv
        error = self._send_aes_cipher_hmac_nonce_seq_send(client_sock)
        if isinstance(error, Exception):
            return error

        # receive hash
        overflow = self._recv_check_hash(client_sock, overflow)
        if isinstance(overflow, Exception):
            return overflow

        # receive `sequence_number_send`
        overflow = self._recv_seq_send(client_sock, overflow)
        if isinstance(overflow, Exception):
            return overflow

        # send hash of sequence_number_send
        error = self._send_hash(client_sock)
        if isinstance(error, Exception):
            return error

        # clean up
        self._clean_up()

        # return possible overflow
        return overflow

    def get_seq_num_send_bytes(self) -> bytes:
        """# `get_seq_num_send_bytes`
        Updates sequence number send and returns the correct sequence of bytes
        reppresenting the sequence number to use in the packet
        """
        self.sequence_number_send = (self.sequence_number_send + 1) % self.max_seq_num
        s = str(self.sequence_number_send)
        while len(s) < self.max_len_seq_num:
            s = "0" + s
        return s.encode("utf-8")

    def get_seq_num_recv_bytes(self) -> bytes:
        """# `get_seq_num_recv_bytes`
        Updates sequence number recv and returns the correct sequence of bytes
        reppresenting the sequence number to use in the packet
        """
        self.sequence_number_recv = (self.sequence_number_recv + 1) % self.max_seq_num
        s = str(self.sequence_number_recv)
        while len(s) < self.max_len_seq_num:
            s = "0" + s
        return s.encode("utf-8")

    def _send_packet(
        self, client_sock: socket, packet: bytes
    ) -> None | HandshakeFailed:
        """
        `exchange`'s helper
        """
        pack_len = len(packet)
        total_sent = 0
        while total_sent < pack_len:
            bytes_sent = client_sock.send(packet[total_sent:])
            if bytes_sent == 0:
                return HandshakeFailed("Failed to send packet")
            total_sent = total_sent + bytes_sent

    def _receiving_packet(
        self, client_sock: socket, pack_len: int, overflow: bytes
    ) -> tuple[bytes, bytes] | HandshakeFailed:
        """
        `exchange`'s helper
        """
        packet = overflow
        total_received = len(overflow)
        while total_received < pack_len:
            received = client_sock.recv(512)
            if received == b"":
                return HandshakeFailed("Failed to receive a packet")
            total_received = total_received + len(received)
            packet = packet + received
        p = packet[:pack_len]
        o = packet[pack_len:]
        return (p, o)

    def _recv_nonce_rsa(self, client_sock: socket) -> bytes | bytes | HandshakeFailed:
        """
        `exchange`'s helper
        """
        pack_len = 251 + self.nonce_length
        tup = self._receiving_packet(client_sock, pack_len, b"")
        if isinstance(tup, Exception):
            return HandshakeFailed(
                "Encrypted handshake failed. Failed to receive nonce and public rsa key."
            )
        packet, overflow = tup

        self.nonce_recv = packet[: self.nonce_length]
        pub_rsa_key_bytes = packet[self.nonce_length : pack_len]
        self.pub_rsa_key = rsa.PublicKey.load_pkcs1(pub_rsa_key_bytes, format="PEM")

        self.hash_function = hashlib.sha512()
        self.hash_function.update(
            self.nonce_recv + self.shared_secret + pub_rsa_key_bytes
        )
        hash = self.hash_function.hexdigest().encode("utf-8")

        return overflow, hash

    def _send_aes_cipher_hmac_nonce_seq_send(
        self, client_sock: socket
    ) -> None | HandshakeFailed:
        """
        `exchange`'s helper
        """
        # generate aes key, aes cipher, hmac key, nonce, seq number send
        salt = get_random_bytes(32)
        pass_phrase = os.urandom(12).hex()
        self.aes_key = PBKDF2(pass_phrase, salt, dkLen=32)
        self.encryption_cipher = AES.new(self.aes_key, AES.MODE_CBC)
        self.decryption_cipher = AES.new(
            self.aes_key, AES.MODE_CBC, iv=self.encryption_cipher.iv
        )
        self.hmac_key = "".join(
            random.choices(string.printable, k=self.hmac_key_length)
        ).encode("utf-8")
        self.nonce_sent = "".join(
            random.choices(string.printable, k=self.nonce_length)
        ).encode("utf-8")
        self.sequence_number_recv = random.randint(0, self.max_seq_num - 1)

        # send aes_key, initial vector, nonce
        packet = self.aes_key + self.encryption_cipher.iv + self.nonce_sent
        packet = rsa.encrypt(packet, self.pub_rsa_key)
        error = self._send_packet(client_sock, packet)
        if error is not None:
            return HandshakeFailed("Failed to send aes key, initial vector, nonce")

        # send hmac_key + initial seq number
        str_seq = str(self.sequence_number_recv)
        len_str_seq = len(str_seq)
        if len_str_seq < self.max_len_seq_num:
            str_seq = "0" * (self.max_len_seq_num - len_str_seq) + str_seq
        packet = self.hmac_key + str_seq.encode("utf-8")
        packet = rsa.encrypt(packet, self.pub_rsa_key)
        error = self._send_packet(client_sock, packet)
        if error is not None:
            return HandshakeFailed("Failed to send hmac key and seq number.")

    def _recv_check_hash(
        self, client_sock: socket, overflow: bytes
    ) -> bytes | HandshakeFailed:
        """
        `exchange`'s helper
        """
        packet = overflow
        pack_len = 128
        total_received = 0
        while total_received < pack_len:
            received = client_sock.recv(512)
            if received == b"":
                return HandshakeFailed(
                    "Encrypted handshake failed. Failed to receive aes key, initial vector and nonce."
                )
            total_received = total_received + len(received)
            packet = packet + received
        recv_hash = packet[:pack_len]
        # the overflow will never happen
        overflow = packet[pack_len:]

        # sending hash of the transaction
        self.hash_function.update(
            self.nonce_sent
            + self.shared_secret
            + self.aes_key
            + self.hmac_key
            + str(self.sequence_number_recv).encode("utf-8")
        )
        hash = self.hash_function.hexdigest().encode("utf-8")

        if hash != recv_hash:
            return HandshakeFailed(
                "Server does not have the correct shared secret, that means that either the secret key is outdated or the server is actually a man in the middle."
            )
        return overflow

    def _recv_seq_send(
        self, client_sock: socket, overflow: bytes
    ) -> bytes | HandshakeFailed:
        """
        `exchange`'s helper
        """
        # NOTE: using AES
        packet = overflow
        pack_len = 16
        total_received = len(overflow)
        while total_received < pack_len:
            received = client_sock.recv(512)
            if received == b"":
                return HandshakeFailed(
                    "Encrypted handshake failed. Failed to receive encrypted sequence_number_send."
                )
            total_received = total_received + len(received)
            packet = packet + received
        try:
            p = self.decryption_cipher.decrypt(packet)
            if p == packet:
                return HandshakeFailed(
                    "Encrypted handshake failed becouse of:\nServer was unable to use our AES key, there are problems on the server side."
                )
            self.sequence_number_send = int(unpad(p, AES.block_size).decode("utf-8"))
        except ValueError as e:
            return HandshakeFailed(f"Encrypted handshake failed becouse of:\n{e}")
        except Exception as e:
            return HandshakeFailed(
                f"Encrypted handshake failed becouse unexpected Exception:\n{e}"
            )
        if (
            self.sequence_number_send < 0
            or self.sequence_number_send > self.max_seq_num - 1
        ):
            return HandshakeFailed("Sequence number exceedes the boundaries")

        return overflow

    def _send_hash(self, client_sock: socket) -> None | HandshakeFailed:
        """
        `exchange`'s helper
        """
        self.hash_function.update(
            str(self.sequence_number_send).encode("utf-8")
            + self.nonce_recv
            + self.shared_secret
        )
        hash = self.hash_function.hexdigest().encode("utf-8")

        packet = hash
        pack_len = len(packet)
        total_sent = 0
        while total_sent < pack_len:
            bytes_sent = client_sock.send(packet[total_sent:])
            total_sent = total_sent + bytes_sent

    def _clean_up(self):
        """
        `exchange`'s helper
        """
        self.nonce_recv = None
        self.nonce_sent = None
        self.pub_rsa_key = None
        self.aes_key = None

    @staticmethod
    def get_id():
        return 2

    def encrypt(self, pack: bytes) -> bytes | EncryptionError:
        payload = self.get_seq_num_send_bytes() + pack
        encrypted_pack = self.encryption_cipher.encrypt(pad(payload, AES.block_size))
        h = hashlib.sha256()
        h.update(encrypted_pack + self.hmac_key)
        hash = h.hexdigest().encode("utf-8")
        pack = encrypted_pack + hash
        return pack

    def decrypt(self, pack: bytes) -> bytes | DecryptionError:
        encrypted_pack = pack[:-64]
        hash_recv = pack[-64:]
        h = hashlib.sha256()
        h.update(encrypted_pack + self.hmac_key)
        hash = h.hexdigest().encode("utf-8")
        if hash != hash_recv:
            return DecryptionError("Hash received is invalid.")
        decrypted_pack = unpad(
            self.decryption_cipher.decrypt(encrypted_pack), AES.block_size
        )
        seq_recv = decrypted_pack[0 : self.max_len_seq_num]
        pack = decrypted_pack[self.max_len_seq_num :]
        seq = self.get_seq_num_recv_bytes()
        if seq != seq_recv:
            return DecryptionError("Wrong sequence number")

        return pack

    def get_packet_size(self, packet_size: int):
        return (
            self.max_len_seq_num
            + packet_size
            + (16 - (self.max_len_seq_num + packet_size % 16))
            + 64
        )


class SymAsymEncHandCL(EncryptionHandler):
    """# `SymAsymEncHandCL`
    Concrete implementation of `EncryptionHandler`, uses RSA algorithm to exchange
    a AES key that will be used for the rest of the communication.
    Client side implementation.
    """

    def __init__(self):
        super().__init__()

    def clone(self):
        return SymAsymEncHandCL()

    def exchange(self, client_sock: socket.socket) -> bytes | Exception:
        # IDEA: two different aes keys for encryption/decryption

        # receive public rsa key
        packet = b""
        pack_len = 251
        total_received = 0
        while total_received < pack_len:
            received = client_sock.recv(512)
            if received == b"":
                return HandshakeFailed(
                    "Encrypted handshake failed. Failed to receive aes key, initial vector and nonce."
                )
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
