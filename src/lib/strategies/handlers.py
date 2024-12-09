import socket
import logging
import sys

from lib.constants import (
    ABSTRACT_METHOD,
    ABSTRACT_SOCKET_HANDLER_ID,
    CONNECTION_CLOSED,
    FIRST_SOCKET_HANDLER_ID,
    NO_LENGTH,
    PACKET_OVERFLOW,
    WRONG_LENGTH,
    APIMisusage,
    ConnectionClosedByOtherSide,
    DecryptionError,
    EncryptionError,
    EncryptionHandlerFailed,
    HandshakeFailed,
    MalformedPacket,
)


class EncryptionHandler:
    """# `EncryptionHandler`
    Abstract class that defines the interface for the functionality of exchanging
    keys, encrypt and decrypt messages between the client and the server; an istance
    of this or a subclass of this will be given as the argument `encryption_handler`
    to a `SocketHandler` instance that will delegate the functionalities aftermentioned
    to this object.
    This abstract class provides default implementation for every method.

    ## Usage
    On the server side a prototypical instance has to be created and `setup` method will need to be called on it.
    Every `SocketHandler` will receive an instance of the prototypical instance using the method
    `clone`.
    On the client side there will probabily no need to call `clone` and the single prototypical instance
    will be sufficient, although is a possibility.
    After obtaining an instance of `EncryptionHandler` or one of its subclasses, the `SocketHandler`
    calls the method `.exchange`, it will exchange all the necessary information with the client;
    then call `.decrypt` to decrypt the packet received and `.encrypt` to encrypt the packet
    that will be sent.
    A method `.get_packet_size` can be used to determine the packet size of a packet to be
    sent if `EncryptionHandler` changes the size of the packet after encrypting it.
    `.get_id` returns an integer identificative of the subclass.
    """

    def __init__(self):
        pass

    def setup(self) -> None | EncryptionHandlerFailed:
        """# `setup`
        Gather all the resources needed for the `EncryptionHandler` to work.
        Returns `None` if everything went fine, `EncryptionHandlerFailed` otherwise.
        Abstract method that provides a default implementation.
        """
        return None

    def clone(self):
        """# `clone`
        Returns an instance of `EncryptionHandler` with that maintains the state of the
        prototype.
        Returns `EncryptionHandler` if everything went fine, a `EncryptionHandlerFailed`
        otherwise.
        Abstract method that provides a default implementation.
        """
        return EncryptionHandler()

    def exchange(self, __client_sock__: socket.socket) -> bytes | HandshakeFailed:
        """# `exchange`
        Exchanges all the information needed for the encryption and decryption
        of the packets, this information will be stored in the object itself,
        returns bytes that have overflown during the exchange(bytes that have
        been passed to the socket after the exchange has completed and have been
        received during the exchange).
        Returns `HandshakeFailed` subclass of `Exception` in case of failure.
        """
        return b""

    def decrypt(self, packet: bytes) -> bytes | DecryptionError:
        """# `decrypt`
        Decrypts `packet`, returns an `Exception` if unsuccessful.
        """
        return packet

    def encrypt(self, packet: bytes) -> bytes | EncryptionError:
        """# `encrypt`
        Encrypts `packet`, returns an `Exception` if unsuccessful.
        """
        return packet

    def get_packet_size(self, packet_size: int):
        """# `get_packet_size`
        Some EncryptionHandler concrete implementation may change the size of the
        packet to be transmitted once the packet gets encrypted by it, this method
        takes the size of the packet that will have to be encrypted and
        allows you to understand which will the size of the packet be after the packet
        will be encrypted, if it is possible to determine this just by the size of
        the original packet, if it is not possible to understand the size of
        the encrypted packet just by the size of the original packet an Exception
        will be returned.
        This is a default implementation.
        """
        return packet_size

    @staticmethod
    def get_id():
        """# `get_id`
        TODO: we need to rethink this one, probabily we will need to build a
        register or something becouse every subclass needs to have its own unique
        identificative code.
        """
        return 0


class SocketHandler:
    """# `SocketHandler`
    Category of classes dedicated to handle the socket that client and server use
    to communicate.
    While overwriting methods of this class keep in mind the methods
    belonging to `EncryptionHandler`.
    This is an abstract class that obeys to the strategy object oriented design pattern.
    """

    def __init__(
        self,
        max_word_size: int,
        client_sock: socket.socket,
        encryption_handler: EncryptionHandler,
        default_timeout: int | None = None,
    ):
        # The maximum length of the payload
        self.max_word_size = max_word_size
        # The maximum length of the length of the payload(amount of digit)
        self.len_max_word_size: int = len(str(self.max_word_size))
        self.internal_receive_buffer: bytes = b""
        self.client_sock = client_sock
        self.byte_count_receive_buffer = 0
        self.byte_count_send_buffer = 0
        self.new_word_mod = True
        self.encryption_handler = encryption_handler

        # set timeout
        if default_timeout is None:
            self.default_timeout = 5000
        else:
            self.default_timeout = default_timeout

    def setup(self) -> None | Exception:
        """# `setup`
        This function sets up the connection handler,
        it carries out all the procedure necessary for the
        handler to work, for example exchanging encryption
        keys.
        Default implementation is provided.
        """
        return None

    def receive(self) -> bytes | Exception:
        """# `receive`
        Abstract method.
        Receives bytes from the socket and packs it, before returning it
        to the caller.
        The user can use provided property to maintain an internal status
        that allows to not truncate packets or something.
        No default implementation provided.
        """
        # TODO: custom exception. This should be a critical error
        return APIMisusage(ABSTRACT_METHOD)

    def send(self, __msg__: bytes) -> int | Exception:
        """# `send`
        Send a message to the communicating remote process.
        Returns an `int` indicating the amount of bytes sent or
        an `Exception` if the procedure failed.
        This is an abstract method that doesn't provide a
        default implementation.
        """
        return APIMisusage(ABSTRACT_METHOD)

    def close(self):
        """# `close`
        Closes the socket and provide eventual terdown procedures.
        Default implementation provided.
        """
        self.client_sock.close()

    def get_id(self) -> int:
        """TODO: Docstring for get_id.
        :returns: TODO

        """
        return ABSTRACT_SOCKET_HANDLER_ID

    def set_timeout(self, timeout: int):
        """# `set_timeout`"""
        self.client_sock.settimeout(timeout)

    def reset_timeout(self):
        """# `reset_timeout`"""
        self.client_sock.settimeout(self.default_timeout)


class PlainSocketHandler(SocketHandler):
    """# `PlainSocketHandler`
    Simplest example of subclass of socket handler.
    IDEA: make this the default implementation of `SocketHandler`
    """

    def __init__(
        self,
        max_word_size: int,
        client_sock: socket.socket,
        encryption_handler: EncryptionHandler,
        default_timeout: int | None = None,
    ):
        super().__init__(
            max_word_size, client_sock, encryption_handler, default_timeout
        )
        # set timeout
        # TODO: decidere cosa fare per il timeout:
        # se il mitente non scrive niente per più
        # di tot secondi il timeout si attiva
        client_sock.settimeout(5000)

    def setup(self) -> None | Exception:
        self.client_sock.settimeout(self.default_timeout)

    def receive(self) -> bytes | Exception:
        """# `receive`
        Receives packet of fixex length, receives bytes until length is reached or
        something wrong occurred.
        If something wrong occurred an Exception is returned, otherwise the packet is
        returned.
        Things that can go wrong: malformed packet, packet overflow, incoherent metadata.
        Packet structure: `[0-9]{len_max_word_size}[.]{max_word_size}`
        """
        while True:
            # buffer is too short, wi still don't have the length of the word
            if self.byte_count_receive_buffer < self.len_max_word_size:
                buffer = self._internal_receive()
                if buffer is not None:
                    self._reset_receive_buffer()
                    return buffer
                continue

            # try to parse the length of the packet
            try:
                buffer_len = int(self.internal_receive_buffer[: self.len_max_word_size])
            except ValueError as e:
                self._reset_receive_buffer()
                return MalformedPacket(NO_LENGTH)
            except Exception as e:
                self._reset_receive_buffer()
                logging.exception(e)
                return e

            # closed socket
            if buffer_len == 0:
                self._reset_receive_buffer()
                return ConnectionClosedByOtherSide(CONNECTION_CLOSED)

            # word is too long
            if buffer_len > self.max_word_size + self.len_max_word_size:
                self._reset_receive_buffer()
                return MalformedPacket(PACKET_OVERFLOW)

            # we don't have the entire word yet
            internal_len = len(self.internal_receive_buffer)
            if internal_len < buffer_len + self.len_max_word_size:
                buffer = self._internal_receive()
                if buffer is not None:
                    self._reset_receive_buffer()
                    return buffer
                continue
            break

        word = self.internal_receive_buffer[
            self.len_max_word_size : buffer_len + self.len_max_word_size
        ]
        # Length of the header different from the length of the actual word
        if len(word) != buffer_len:
            self._reset_receive_buffer()
            return MalformedPacket(WRONG_LENGTH)
        # Flush the newly received word
        self.internal_receive_buffer = self.internal_receive_buffer[
            self.len_max_word_size + buffer_len :
        ]
        self.byte_count_receive_buffer = len(self.internal_receive_buffer)
        return word

    def send(self, msg: bytes) -> int | Exception:
        msg_size = len(msg)
        if msg_size > self.max_word_size:
            return MalformedPacket(PACKET_OVERFLOW)
        msg_size_prefix = str(msg_size).encode("utf-8")

        len_msg_size = len(msg_size_prefix)
        # calculate length prefix
        diff = self.len_max_word_size - len_msg_size
        for _ in range(0, diff):
            msg_size_prefix = b"0" + msg_size_prefix

        pack = msg_size_prefix + msg

        try:
            return self._internal_send(pack)
        except Exception as e:
            return e

    def get_id(self) -> int:
        """TODO: Docstring for get_id.
        :returns: TODO

        """
        return FIRST_SOCKET_HANDLER_ID

    def _internal_receive(self) -> None | Exception:
        """# `_internal_receive`
        `receive`'s helper function, receives the packet form the socket,
        updates `SocketHandler.internal_receive_buffer` and
        `SocketHandler.byte_count_receive_buffer`,
        returns None if everything went well,
        an exception otherwise, in case an error occurred
        `SocketHandler.internal_receive_buffer` and
        `SocketHandler.byte_count_receive_buffer` reset.
        """

        try:
            buffer = self.client_sock.recv(512)
            if buffer == b"":
                return ConnectionClosedByOtherSide(CONNECTION_CLOSED)
        except (TimeoutError, OSError) as e:
            return e
        except Exception as e:
            logging.exception(e)
            return e
        self.internal_receive_buffer = self.internal_receive_buffer + buffer
        self.byte_count_receive_buffer = self.byte_count_receive_buffer + len(buffer)

        return None

    def _internal_send(self, pack: bytes) -> int | Exception:
        """TODO: Docstring for _internal_send.
        :returns: TODO

        """
        total_sent = 0
        length = len(pack)
        while total_sent < length:
            sent = self.client_sock.send(pack[total_sent:])
            if sent == 0:
                return ConnectionClosedByOtherSide(CONNECTION_CLOSED)
            total_sent = total_sent + sent
        return total_sent

    def _reset_receive_buffer(self):
        """# `_reset_receive_buffer`
        `receive`'s helper function, reset's `SocketHandler.internal_receive_buffer`
        and `SocketHandler.byte_count_receive_buffer`
        """
        self.internal_receive_buffer = b""
        self.byte_count_receive_buffer = 0


class EncryptSocketHandler(SocketHandler):
    """# `EncryptSocketHandler`
    Concrete implementation of `SocketHandler`.
    ## Subclass specific characteristics
    The packets of this specific subclass all have the same size, the
    final size of the packet is influenced by the chosen `encryption_handler`.
    The packet will contain a maximum of one word for packet, if the sender
    tries to send a word that exceeds the maximal length of the word allowed
    the word will be split in multiple packets.
    The first bytes of the packet determine the size of the word, the amount of
    bytes that determine this characteristic is dependant of `max_word_size`
    provided by the client.
    """

    def __init__(
        self,
        max_word_size: int,
        client_sock: socket.socket,
        encryption_handler: EncryptionHandler,
        default_timeout: int | None = None,
    ):
        super().__init__(
            max_word_size, client_sock, encryption_handler, default_timeout
        )
        # At most one word for packet
        self.max_packet_len = self.max_word_size + self.len_max_word_size
        # Size of the encrypted and padded packet
        self.padded_packet_len: int = None

    def setup(self) -> None | Exception:
        self.client_sock.settimeout(self.default_timeout)

        overflow = self.encryption_handler.exchange(self.client_sock)
        if isinstance(overflow, Exception):
            return overflow

        self.internal_receive_buffer = self.internal_receive_buffer + overflow
        self.byte_count_receive_buffer = self.byte_count_receive_buffer + len(overflow)

        # TODO: error handling: not sure about what the interface
        # for `EncryptionHandler.get_packet_size()` is going to be,
        # so for the time being we are just going to return an error
        # if the concrete implementation of `EncryptionHandler`
        # returns an exception.
        self.padded_packet_len = self.encryption_handler.get_packet_size(
            self.max_packet_len
        )
        if isinstance(self.padded_packet_len, Exception):
            return self.padded_packet_len

        return None

    def receive(self) -> bytes | Exception:
        while True:

            # We still don't have an entire packet
            if self.byte_count_receive_buffer < self.padded_packet_len:
                error = self._internal_receive()
                if error is not None:
                    return error
                continue

            # Decode a packet
            # extract packet, adjust infos
            encoded_sub_packet = self.internal_receive_buffer[: self.padded_packet_len]
            sub_packet = self.encryption_handler.decrypt(encoded_sub_packet)
            if isinstance(sub_packet, Exception):
                return sub_packet
            self.internal_receive_buffer = self.internal_receive_buffer[
                self.padded_packet_len :
            ]
            self.byte_count_receive_buffer = (
                self.byte_count_receive_buffer - self.padded_packet_len
            )

            # Extract the word from the packet
            try:
                word_total_len = int(sub_packet[: self.len_max_word_size])
            except ValueError as e:
                return MalformedPacket(PACKET_OVERFLOW)
            except Exception as e:
                logging.exception(e)
                return e

            if word_total_len > self.max_word_size:
                return MalformedPacket(PACKET_OVERFLOW)

            word = sub_packet[
                self.len_max_word_size : word_total_len + self.len_max_word_size
            ]
            return word

    def _internal_receive(self) -> None | Exception:
        """# `_internal_receive`
        `receive`'s helper function, receives the packet form the socket,
        updates `SocketHandler.internal_receive_buffer` and
        `SocketHandler.byte_count_receive_buffer`,
        returns None if everything went well,
        an exception otherwise, in case an error occurred
        `SocketHandler.internal_receive_buffer` and
        `SocketHandler.byte_count_receive_buffer` will be reset.
        """
        try:
            buffer = self.client_sock.recv(self.padded_packet_len)
            if buffer == b"":
                return ConnectionClosedByOtherSide(CONNECTION_CLOSED)
        except (TimeoutError, OSError) as e:
            return e
        except Exception as e:
            print("Unexpected error occured!", file=sys.stderr)
            logging.exception(e)
            return e
        self.internal_receive_buffer = self.internal_receive_buffer + buffer
        self.byte_count_receive_buffer = self.byte_count_receive_buffer + len(buffer)

    def send(self, msg: bytes) -> int | Exception:
        total_total_sent = 0
        # build the packet
        msg_size = len(msg)
        while msg_size > 0:
            if msg_size <= self.max_word_size:
                unsent = msg[: self.max_word_size]
                msg = msg[self.max_word_size :]
            else:
                unsent = msg[: self.max_word_size - 3] + b"..."
                msg = msg[self.max_word_size - 3 :]
            unsent_size = len(unsent)
            msg_size = len(msg)

            unsent_size_prefix = str(unsent_size).encode("utf-8")
            len_unsent_size_prefix = len(unsent_size_prefix)
            # calculate length prefix
            diff = self.len_max_word_size - len_unsent_size_prefix
            unsent_size_prefix = b"0" * diff + unsent_size_prefix
            unsent_pack = unsent_size_prefix + unsent
            # padding
            total_pack_len = len(unsent_pack)
            unsent_pack = unsent_pack + b"0" * (self.max_packet_len - total_pack_len)
            # encrypt
            encoded_pack = self.encryption_handler.encrypt(unsent_pack)
            # send
            total_sent = 0
            while self.padded_packet_len > total_sent:
                sent = self.client_sock.send(encoded_pack[total_sent:])
                if sent == 0:
                    return ConnectionClosedByOtherSide(CONNECTION_CLOSED)
                total_sent = total_sent + sent
                total_total_sent = total_total_sent + sent

        return total_total_sent
