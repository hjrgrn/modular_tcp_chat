import logging
import socket
import threading

from random import randrange

from lib.constants import SHUTDOWN
from lib.strategies.handlers import (
    EncryptionHandler,
    SocketHandler,
)
from server.config import ServerConfiguration
from server.strategies.handshakes import Client, HandshakeServerSide


class Master:
    """Docstring for Master."""

    def __init__(
        self,
        handshake_strategy: HandshakeServerSide,
        socket_handler: SocketHandler,
        encryption_handler: EncryptionHandler,
        configuration: ServerConfiguration,
    ):
        self.addr = configuration.address
        self.port = configuration.port
        self.max_word_size = configuration.max_word_size
        self.welcoming_sock: socket.socket = None
        self.handshake_handler: HandshakeServerSide = handshake_strategy(self)
        self.socket_handler: SocketHandler = socket_handler
        self.encryption_handler: EncryptionHandler = encryption_handler()
        self.max_clients = configuration.max_clients
        # TODO: use a `queue.Queue` for `self.clients` or something that is
        # threading safe, since a handshake handler could use it inside a
        # separate thread, maybe a specific worker that handles the client and
        # communicate with queues
        self.clients: list[Client] = []
        self.active = True
        self.configuration = configuration

    def run(self) -> None | Exception:
        """# `run`
        Method that runs the server.
        """
        logging.info("Setting up encryption handler")
        # encryption handler setup
        error = self.encryption_handler.setup()
        if error is not None:
            return error
        logging.info("Setting up handshake handler")
        # handshake handler setup
        error = self.handshake_handler.setup()
        if error is not None:
            return error

        self.welcoming_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.welcoming_sock.settimeout(5)
        try:
            self.welcoming_sock.bind((self.addr, self.port))
        except (ValueError, OSError, TypeError) as error:
            return error
        except Exception as error:
            # Unexpected behaviour
            logging.exception(error)
            return error
        self.welcoming_sock.listen()
        logging.info(f"Listening on address: {self.addr}:{self.port}")
        self._receive_client()

        self._set_timeouts(1)
        self._broadcast(SHUTDOWN.encode("utf-8"), None)
        for client in self.clients:
            client.socket_handler.close()
            # TODO: do something with error
            error = self.handshake_handler.remove_client(client.id)
        # TODO: do something with error
        error = self.handshake_handler.teardown()
        self.welcoming_sock.close()

    def is_nickname_avaible(self, nickname: str) -> bool:
        """# `is_nickname_avaible`
        This function returns if wheather or not a specific nickname is avaible
        """
        avaible = True
        for client in self.clients:
            if client.nickname == nickname:
                avaible = False
                break
        return avaible

    def get_free_id(self):
        """# `get_free_id`
        Obtains an id that is not assaigned yet
        """
        found = False
        while found == False:
            potential_id = randrange(self.max_clients * 100)
            found = True
            for client in self.clients:
                if client.id == potential_id:
                    found = False
                    continue
        return potential_id

    def _set_timeouts(self, interval: int):
        """# `_set_timeouts`
        Set timeout constraint for every client connected.
        """
        for client in self.clients:
            client.socket_handler.set_timeout(interval)

    def _receive_client(self):
        """# `_receive_client`
        Runs until the server is deactivated, receives requests of clinets
        trying to connect, allocates resources necessary for the communication,
        eventually filters incoming requests(based on the chosen `handshake_handler`),
        starts a thread on which the connection will be handled.
        """
        while self.active == True:
            # NOTE: we set the timeout to 5 second on the receiving socket,
            # this way every 5 seconds accept will fail and be called again,
            # otherwise it keeps on going forever, that is a solution to acheive
            # a proper shutdown, I don't know if this is the best way of implementing
            # it.
            try:
                client_sock, address = self.welcoming_sock.accept()
            except TimeoutError:
                continue

            # Initiating the socket handler for the specific connection
            # NOTE: we are allocating this resources before authenticating the user,
            # this may cause a dos vulnerability: trying to think of a way to mitigate
            # that at application layer
            socket_handler = self.socket_handler(
                self.max_word_size, client_sock, self.encryption_handler.clone()
            )
            error = socket_handler.setup()
            if error is not None:
                logging.info(f"{error}")
                continue

            logging.info(f"Connected with {str(address)}")

            client = self.handshake_handler.connect(socket_handler)
            # Failed handshake
            if not isinstance(client, Client):
                logging.info(f"Handshake failed with client: {address}\n{client}")
                continue
            # Successful handshake
            logging.info(f"Client {client.nickname} has joined the chat")
            self._broadcast(
                f"{client.nickname} has joined the chat.\n".encode("utf-8"), "Master"
            )

            self.clients.append(client)

            thread = threading.Thread(
                target=self._handler_worker, args=(client,), daemon=True
            )
            thread.start()

    def _broadcast(self, msg: bytes, nickname: str | None):
        """# `_broadcast`
        Broadcasts a message to all the clients connected.
        If it was impossible to deliver said message the
        client will be removed.
        """
        if nickname is not None:
            msg = nickname.encode("utf-8") + b": " + msg
            print(msg.decode("utf-8"))

        clients_to_be_removed: list[Client] = []

        for client in self.clients:
            if client.nickname != nickname:
                length = client.socket_handler.send(msg)
                if not isinstance(length, int):
                    clients_to_be_removed.append(client)

        for client in clients_to_be_removed:
            self._client_left(client)

    def _handler_worker(self, client: Client):
        """# `_handler_worker`
        Handles a connection in a thread specific for said connection.
        """
        while True:
            msg = client.socket_handler.receive()
            if isinstance(msg, Exception):
                logging.info(msg)
                break
            msg = self.handshake_handler.authenticate_msg(msg)
            # The message is not authentic
            if isinstance(msg, Exception):
                logging.info(msg)
                break
            self._broadcast(msg, client.nickname)

        self._client_left(client)

    def _client_left(self, client: Client):
        """# `_client_left`
        When `client` leaves the chat this method is called,
        removes the client from the clients pool and closes its socket,
        then broadcasts that the client left.
        """
        client.socket_handler.close()
        self.clients.remove(client)
        __error__ = self.handshake_handler.remove_client(client.id)
        # TODO: do something with the error
        self._broadcast(
            f"{client.nickname} has left the chat".encode("utf-8"), "Master"
        )

    def _handshake(self, socket_handler: SocketHandler) -> Client | str:
        """# _handshake
        Delegates handshake functionalities to an `HandshakeServerSide` object.
        """
        return self.handshake_handler.connect(socket_handler, self)

    def graceful_shutdown(self):
        """TODO: Stil thinking about what this will look like"""
        self.active = False
