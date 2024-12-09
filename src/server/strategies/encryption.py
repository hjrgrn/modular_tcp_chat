from getpass import getpass
import hashlib
import logging
import random
import socket
import string

import rsa
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

from lib.constants import (
    DecryptionError,
    EncryptionError,
    HandshakeFailed,
    EncryptionHandlerFailed,
)
from lib.strategies.handlers import EncryptionHandler


class SharedSecretSS(EncryptionHandler):
    """# SharedSecretSS

    ## Description

    Concrete implementation of `EncryptionHandler`.
    This implementation uses an RSA key to exchange a AES key (both specific for every single connection), the last one will be used during the final part of the exchange and during the session.
    During the exchange nonces, sha512 hashes, a shared secret(collected interactively) and a hmac key are used to verify the integrity of the exchange in order to prevent: playback attacks, segment replay attacks, spoofing(server side and client side); hopefully.
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
        self.max_len_seq_num: int = len(str(self.max_seq_num).encode("utf-8"))
        self.encryption_cipher = None
        self.decryption_cipher = None
        self.hmac_key: bytes = None
        # TODO: make this configurable
        self.hmac_key_length: int = 64
        # NOTE: These will be cleaned after exchange
        self.priv_rsa_key: rsa.PrivateKey | None = None
        self.pub_rsa_key: rsa.PublicKey | None = None
        self.pub_rsa_key_bytes: bytes | None = None
        self.nonce_sent: bytes | None = None
        self.hash_function = hashlib.sha512()
        # TODO: make this configurable
        self.nonce_length: int = 64
        self.aes_key: bytes | None = None

    def setup(self) -> None | EncryptionHandlerFailed:
        """# `setup`
        Requires the insertion of a secret that will have to be shared with
        the clients in a secure way, without said secret the client won't be
        able to connect.
        """
        self.shared_secret = getpass("Type in your shared secret: ").encode("utf-8")

    def clone(self):
        cloned = SharedSecretSS()
        cloned.shared_secret = self.shared_secret
        return cloned

    def exchange(self, client_sock: socket.socket) -> bytes | HandshakeFailed:
        self.nonce_sent = self._send_nonce_rsa(client_sock)
        if isinstance(self.nonce_sent, Exception):
            return self.nonce_sent

        # receive hash
        # NOTE: receiving hash now in order to cut the connection earlier if it client is not authorized
        overflow = self._recv_hash_nonce_rsa(client_sock)
        if isinstance(overflow, Exception):
            return overflow

        # receive (aes key + initial vector +  nonce) packet
        packet = self._recv_aes_iv_nonce(client_sock, overflow)
        if isinstance(packet, Exception):
            return packet
        nonce_recv, overflow = packet

        # receive hmac_key + sequence_number_send
        overflow = self._recv_hmac_seq_send(client_sock, overflow)
        if isinstance(overflow, Exception):
            return overflow

        # sending hash of the transaction
        error = self._send_hash(client_sock, nonce_recv)
        if error is not None:
            return error

        # Send `sequence_number_recv`
        # NOTE: using AES from now on
        error = self._send_seq_recv(client_sock)
        if isinstance(error, Exception):
            return error

        # Receiving hash
        overflow = self._recv_check_hash(client_sock, overflow)
        if isinstance(overflow, Exception):
            return overflow

        # Clean up
        self._clean_up()

        # return possible overflow
        return overflow

    def get_seq_num_send_bytes(self) -> bytes:
        """# `get_seq_num_send_bytes`
        Updates sequence number send and returns the correct sequence of bytes
        reppresenting the sequence number to use in the packet
        """
        # TODO: code duplication client side
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
        # TODO: code duplication client side
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
        # TODO: duplication in the client side
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
        # TODO: duplication in the client side
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

    def _send_nonce_rsa(self, client_sock: socket) -> bytes | HandshakeFailed:
        """
        `exchange`'s helper
        """
        nonce_sent = "".join(
            random.choices(string.printable, k=self.nonce_length)
        ).encode("utf-8")
        self.pub_rsa_key, self.priv_rsa_key = rsa.newkeys(1024)
        self.pub_rsa_key_bytes = self.pub_rsa_key.save_pkcs1(format="PEM")
        packet = nonce_sent + self.pub_rsa_key_bytes
        error = self._send_packet(client_sock, packet)
        if error is not None:
            return HandshakeFailed("Failed to send nonce and public RSA key")
        return nonce_sent

    def _recv_hash_nonce_rsa(self, client_sock: socket) -> bytes | HandshakeFailed:
        """
        `exchange`'s helper
        """
        tup = self._receiving_packet(client_sock, 128, b"")
        if isinstance(tup, Exception):
            return HandshakeFailed(
                "Encrypted handshake failed. Failed to receive hash of nonce + pub rsa."
            )
        (recv_hash, overflow) = tup

        self.hash_function.update(
            self.nonce_sent + self.shared_secret + self.pub_rsa_key_bytes
        )
        hash = self.hash_function.hexdigest().encode("utf-8")
        if recv_hash != hash:
            return HandshakeFailed(
                "Client presented a different hash of the informations provided, it doesn't have the correct shared secret key, it is not authorized."
            )
        return overflow

    def _recv_aes_iv_nonce(
        self, client_sock: socket, overflow: bytes
    ) -> tuple[bytes, bytes] | HandshakeFailed:
        """
        `exchange`'s helper
        """
        tup = self._receiving_packet(client_sock, 128, overflow)
        if isinstance(tup, Exception):
            return HandshakeFailed(
                "Encrypted handshake failed. Failed to receive aes key, initial vector and nonce."
            )
        (encrypted_pack, overflow) = tup

        # decrypt packet
        try:
            packet = rsa.decrypt(encrypted_pack, self.priv_rsa_key)
        except rsa.DecryptionError as e:
            return HandshakeFailed(f"Handshake failed becouse of:\n{e.__repr__()}")
        except Exception as e:
            # Unexpected error
            logging.exception(e)
            return HandshakeFailed(f"Handshake failed becouse of:\n{e.__repr__()}")

        self.aes_key = packet[:32]
        iv = packet[32 : 32 + 16]
        nonce_recv = packet[32 + 16 : 32 + 16 + self.nonce_length]

        # generate ciphers
        # NOTE: same encryption key is used for encryption and decryption
        self.encryption_cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=iv)
        self.decryption_cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=iv)

        return nonce_recv, overflow

    def _recv_hmac_seq_send(
        self, client_sock: socket, overflow: bytes
    ) -> bytes | HandshakeFailed:
        """
        `exchange`'s helper
        """
        tup = self._receiving_packet(client_sock, 128, overflow)
        if isinstance(tup, Exception):
            return HandshakeFailed(
                "Encrypted handshake failed. Failed to receive hmac key and sequence_number_send."
            )
        (encrypted_pack, overflow) = tup

        # decrypt packet
        try:
            packet = rsa.decrypt(encrypted_pack, self.priv_rsa_key)
        except rsa.DecryptionError as e:
            return HandshakeFailed(f"Handshake failed becouse of:\n{e.__repr__()}")
        except Exception as e:
            # Unexpected error
            logging.exception(e)
            return HandshakeFailed(f"Handshake failed becouse of:\n{e.__repr__()}")

        if len(packet) != 64 + 4:
            return HandshakeFailed("A malformed packet has been provided")
        self.hmac_key = packet[:64]
        sequence_number_send_str = packet[64 : 64 + 4]
        try:
            self.sequence_number_send = int(sequence_number_send_str.decode("utf-8"))
        except ValueError as e:
            return HandshakeFailed("A malformed packet has been provided")
        except Exception as e:
            return HandshakeFailed(f"Unexpected behaviour:\n{e}")
        if (
            self.sequence_number_send > self.max_seq_num - 1
            or self.sequence_number_send < 0
        ):
            return HandshakeFailed("Sequence number exceedes the boundaries")

        return overflow

    def _send_hash(
        self, client_sock: socket, nonce_recv: bytes
    ) -> None | HandshakeFailed:
        """
        `exchange`'s helper
        """
        self.hash_function.update(
            nonce_recv
            + self.shared_secret
            + self.aes_key
            + self.hmac_key
            + str(self.sequence_number_send).encode("utf-8")
        )
        hash = self.hash_function.hexdigest().encode("utf-8")

        error = self._send_packet(client_sock, hash)
        if error is not None:
            return HandshakeFailed("Failed to send hash.")

    def _send_seq_recv(self, client_sock: socket) -> None | HandshakeFailed:
        """
        `exchange`'s helper
        """
        # NOTE: using AES
        self.sequence_number_recv = random.randint(0, self.max_seq_num - 1)
        str_seq = str(self.sequence_number_recv)
        len_str_seq = len(str_seq)
        if len_str_seq < self.max_len_seq_num:
            str_seq = "0" * (self.max_len_seq_num - len_str_seq) + str_seq
        packet = str_seq.encode("utf-8")
        error = self._send_packet(
            client_sock, self.encryption_cipher.encrypt(pad(packet, AES.block_size))
        )
        if error is not None:
            return HandshakeFailed("Failed to send sequence number")
        pass

    def _recv_check_hash(
        self, client_sock: socket, overflow: bytes
    ) -> bytes | HandshakeFailed:
        """
        `exchange`'s helper
        """
        tup = self._receiving_packet(client_sock, 128, overflow)
        if isinstance(tup, Exception):
            return HandshakeFailed(
                "Encrypted handshake failed. Failed to receive hash of sequence number."
            )
        (hash_recv, overflow) = tup

        # Producing hash
        self.hash_function.update(
            str(self.sequence_number_recv).encode("utf-8")
            + self.nonce_sent
            + self.shared_secret
        )
        hash = self.hash_function.hexdigest().encode("utf-8")

        if hash != hash_recv:
            return HandshakeFailed("User provided wrong hash of sequence_number_recv")

        return overflow

    def _clean_up(self):
        """
        `exchange`'s helper
        """
        self.priv_rsa_key = None
        self.pub_rsa_key = None
        self.pub_rsa_key_bytes = None
        self.nonce_sent = None
        self.hash_function = None
        self.nonce_length = None
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


class SymAsymEncHandSS(EncryptionHandler):
    """# `SymAsymEncHandSS`
    Concrete implementation of `EncryptionHandler`, uses RSA algorithm to exchange
    a AES session key that will be used for the rest of the communication.
    The same symmetric key is used for encryption and decryption.
    Server side implementation.
    """

    def __init__(self):
        super().__init__()

    def clone(self):
        return SymAsymEncHandSS()

    def exchange(self, client_sock: socket.socket) -> bytes | HandshakeFailed:
        pub_rsa_key, priv_rsa_key = rsa.newkeys(1024)
        packet = pub_rsa_key.save_pkcs1(format="PEM")
        pack_len = len(packet)
        total_sent = 0
        while total_sent < pack_len:
            bytes_sent = client_sock.send(packet[total_sent:])
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

    def encrypt(self, pack: bytes) -> bytes | EncryptionError:
        encrypted = self.encryption_cipher.encrypt(pad(pack, AES.block_size))
        return encrypted

    def decrypt(self, pack: bytes) -> bytes | DecryptionError:
        decrypted = unpad(self.decryption_cipher.decrypt(pack), AES.block_size)
        return decrypted

    def get_packet_size(self, packet_size: int):
        diff = 16 - (packet_size % 16)
        return packet_size + diff
