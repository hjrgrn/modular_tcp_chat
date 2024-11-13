import logging
import socket
import sys
import threading

from client.config import ClientConfiguration
from client.strategies.handshakes import HandshakeClientSide
from lib.constants import KICKED, SHUTDOWN
from lib.strategies.handlers import (
    EncryptionHandler,
    SocketHandler,
)


class ChatClient:
    """ChatClient"""

    def __init__(
        self,
        handshake_strategy: HandshakeClientSide,
        encryption_handler: EncryptionHandler,
        socket_handler: SocketHandler,
        configuration: ClientConfiguration,
    ):
        self.address = configuration.address
        self.port = configuration.port
        self.max_word_size = configuration.max_word_size
        self.handshake_handler: HandshakeClientSide = handshake_strategy()
        self.nickname: str = None
        self.receive_thread: threading.Thread = None
        self.write_thread: threading.Thread = None
        self.event_shutdown = threading.Event()
        self.socket_handler_class = socket_handler
        self.encryption_handler_class = encryption_handler

    def run(self):
        """# run
        Main function that performs the handshake and initializes the
        worker threads.
        """
        error = self.handshake_handler.setup()
        if error is not None:
            print(f"Connection failed becouse of:\n{error}", file=sys.stderr)
            return

        # Initialise the socket handler
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_sock.connect((self.address, self.port))
        except ConnectionRefusedError as e:
            print(f"{e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            # Unexpected behaviour
            logging.exception(e)
            print(f"{e}", file=sys.stderr)
            sys.exit(2)
        self.encryption_handler = self.encryption_handler_class()
        self.socket_handler = self.socket_handler_class(
            self.max_word_size, client_sock, self.encryption_handler
        )
        error = self.socket_handler.setup()
        if error is not None:
            print(f"{error}", file=sys.stderr)
            sys.exit(3)

        self.nickname = self._handshake(self.socket_handler)
        if isinstance(self.nickname, Exception):
            print(f"Connection failed:\n{self.nickname}", file=sys.stderr)
            return

        print("Welcome to the chat, you have been accepted, start chatting!")

        self.receive_thread = threading.Thread(target=self._receive_worker)
        self.receive_thread.start()
        self.write_thread = threading.Thread(target=self._write_worker)
        self.write_thread.start()
        self.receive_thread.join()
        self.write_thread.join()

        self.socket_handler.close()

    def _handshake(self, client_socket: SocketHandler):
        """# _handshake
        Perfom a handshake procedure by delegating the task to the `HandshakeClientSide`
        provided.
        """
        return self.handshake_handler.connect(client_socket)

    def _receive_worker(self):
        """# _receive_worker
        A worker function that will be run by a thread, receives
        information from the socket and prints them to standard out.
        Terminates if a critical error occurs or if `self.event_shutdown`
        is set.
        """
        while True:
            if self.event_shutdown.is_set():
                break
            msg = self.socket_handler.receive()
            if isinstance(msg, Exception):
                if not self.event_shutdown.is_set():
                    self.event_shutdown.set()
                    print(msg, file=sys.stderr)
                break
            msg = msg.decode("utf-8")
            if msg == KICKED:
                print("You have been kicked, shutting down.")
                self.event_shutdown.set()
                break
            elif msg == SHUTDOWN:
                print("Server is shutting down.")
                self.event_shutdown.set()
                break
            else:
                print(msg)

        print("Press <enter> to close the application.")

    def _write_worker(self):
        """# _write_worker
        A worker function that will be run by a thread, receives
        information from stdin that will be sent through the socket
        to the server.
        Terminates if a critical error occurs ot if `self.event_shutdown`
        is set.
        """
        while True:
            if self.event_shutdown.is_set():
                break
            msg = input("")
            length = self.socket_handler.send(msg.encode("utf-8"))
            if isinstance(length, Exception):
                if not self.event_shutdown.is_set():
                    self.event_shutdown.set()
                    print(length, file=sys.stderr)
                break

    def graceful_shutdown(self):
        """# graceful_shutdown
        When this method is invoked the threads of the application
        will shut down.
        """
        print("\nShutting down...press <enter> to close the application.")
        self.event_shutdown.set()
