import getpass
import sys
from lib.auxiliaries import read_from_stdin
from lib.constants import (
    ABSTRACT_METHOD,
    ACCEPTED,
    CONNECTION_REFUSED,
    NICK_NOT_ALPHA_NUM,
    NICK_TAKEN,
    NICK_TOO_LONG,
    NICK_TOO_SHORT,
    REFUSED,
    HandshakeError,
)
from lib.strategies.handlers import SocketHandler


class HandshakeClientSide:
    """# `HandshakeClientSide`
    Abstract class for the Strategy design pattern.
    The objects produced by this class allow a client
    to perform a handshake with the server.
    Coherent `HandshakeClientSide` and `HandshakeServerSide` strategies need
    to be written in order for the application to work.
    """

    def __init__(self):
        pass

    def setup(self) -> None | HandshakeError:
        """# `setup`
        Sets additional resources up so that the handshake handler can work
        correctly.
        This method needs to be called for the client application to work.
        Returns `None` if the handshake handler is functional, an `HandshakeError` if the
        handshake handler can't work.
        This is an abstract method that provides a default implementation that doesn't
        allocate any resource, so it always returns `None`.
        """
        return None

    def connect(self, __socket_handler__: SocketHandler) -> str | HandshakeError:
        """# `connect`
        Connects to the instance of the server.
        Returns a string containing the nickname chosen by the user or
        a `HandshakeError` exception.
        No default implementation provided.
        """
        return HandshakeError(ABSTRACT_METHOD)


class FirstHandshakeClientSide(HandshakeClientSide):
    """PlainHandshakeClientSide"""

    def connect(self, socket_handler: SocketHandler) -> str | HandshakeError:
        socket_handler.set_timeout(30)
        error = None

        while True:
            nick = read_from_stdin(
                "Chose a nickname(max 30 alpha-numerical chars):\n>> ", 30
            )
            if isinstance(nick, Exception):
                error = nick
                break
            nick.encode("utf-8")
            length = socket_handler.send(nick)
            if not isinstance(length, int):
                error = length
                break
            msg = socket_handler.receive()
            if not isinstance(msg, bytes):
                error = msg
                break
            msg = msg.decode("utf-8")
            if msg == ACCEPTED:
                break
            if msg == REFUSED:
                return HandshakeError(CONNECTION_REFUSED)
            elif msg == NICK_TOO_LONG:
                print(
                    "Error: the nickname you have provided is too long, try again.",
                    file=sys.stderr,
                )
                continue
            elif msg == NICK_TOO_SHORT:
                print(
                    "Error: the nickname you have provided is too short, try again.",
                    file=sys.stderr,
                )
                continue
            elif msg == NICK_TAKEN:
                print(
                    "Error: the nickname you have provided is already taken, try again.",
                    file=sys.stderr,
                )
                continue
            elif msg == NICK_NOT_ALPHA_NUM:
                print(
                    "Error: the nickname you have provided has non alpha-numerical characters, try again.",
                    file=sys.stderr,
                )
                continue

        socket_handler.reset_timeout()

        if error:
            return HandshakeError(error.__str__())

        return nick


class BasicAuthHandshakeCS(HandshakeClientSide):
    """# `BasicAuthHandshakeCS`
    This strategy of `HandshakeClientSide` provides functionality for registration and
    basic password authentication.
    """

    def __init__(self):
        self.nick: str = None
        self.email: str = None
        self.mode: str = None
        self.password: str | None = None

    def setup(self) -> None | HandshakeError:
        mode = read_from_stdin(
            "Available actions:\n[1] Login\n[2] Register\n[0] Abort", 1
        )
        if isinstance(mode, Exception):
            return HandshakeError(mode.__str__())
        if mode == "1":
            self.mode = "l"
        elif mode == "2":
            self.mode = "r"
        else:
            return HandshakeError("Unrecognised mode")
        nick = read_from_stdin("Nickname: ", 50)
        if isinstance(nick, Exception):
            return HandshakeError(nick.__str__())
        self.nick = nick
        email = read_from_stdin("Email: ", 300)
        if isinstance(email, Exception):
            return HandshakeError(email.__str__())
        self.email = email
        try:
            # TODO: limit password
            password = getpass.getpass("Password: ")
        except Exception as e:
            return HandshakeError(e.__str__())
        self.password = password
        return None

    def connect(self, socket_handler: SocketHandler) -> str | HandshakeError:
        socket_handler.set_timeout(30)

        if self.mode == "r" or self.mode == "l":
            res = self._register_or_login(socket_handler)
            if isinstance(res, Exception):
                return HandshakeError(res.__str__())
        else:
            # NOTE: this should not happen
            return HandshakeError("Unrecognised mode.")

        res = socket_handler.receive()
        if isinstance(res, Exception):
            return HandshakeError(res.__str__())
        if res.decode("utf-8") != ACCEPTED:
            return HandshakeError("Connection refused.")

        socket_handler.reset_timeout()

        return self.nick

    def _register_or_login(self, socket_handler: SocketHandler) -> None | Exception:
        """# `_register_or_login`, `connect`'s helper.
        Sends login/register informations to the server.
        Returns `None` if everything went fine, an `Exception` otherwise.
        """
        res = socket_handler.send(self.mode.encode("utf-8"))
        if isinstance(res, Exception):
            return res
        res = socket_handler.send(self.nick.encode("utf-8"))
        if isinstance(res, Exception):
            return res
        res = socket_handler.send(self.email.encode("utf-8"))
        if isinstance(res, Exception):
            return res
        res = socket_handler.send(self.password.encode("utf-8"))
        if isinstance(res, Exception):
            return res
        self.password = "#"*200

        return None
