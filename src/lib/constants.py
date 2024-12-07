# TODO: rework this mod

# Ids of the various strategies needed for the abstract factory to work
ABSTRACT_SOCKET_HANDLER_ID = 0
FIRST_SOCKET_HANDLER_ID = 1

# Custom Exceptions for `SocketHandler`
## Messages
NO_LENGTH = "Error: MalformedPacket: I was unable to parse the packet length."
PACKET_OVERFLOW = "Error: MalformedPacket: Peer provided a packet that exceeded the buffer capacity of the socket handler."
WRONG_LENGTH = "Error: MalformedPacket: The length of the packet doesn't coincide with the length expressed in the header."
CONNECTION_CLOSED = "Error: ConnectionClosedByOtherSide: The socket has been closed by the other side of the connection."
MAX_TRIES_REACHED = "Error: Max amount of attempt reached."
CONNECTION_REFUSED = "Error: Connection has been refused by server."


## Exceptions
class MalformedPacket(Exception):
    pass


class ConnectionClosedByOtherSide(Exception):
    pass


class HandshakeFailed(Exception):
    pass


class ServerConfigurationError(Exception):
    pass


class ClientConfigurationError(Exception):
    pass

class EncryptionHandlerFailed(Exception):
    pass

class DecryptionError(Exception):
    pass

class EncryptionError(Exception):
    pass


# Handshake related Exceptions
class HandshakeError(Exception):
    """# `HandshakeError`

    Custom `Exception` returned by a `HandshakeServerSide` or `HandshakeClientSide`, communicating
    that the server cannot function and needs to shut down.
    """

    pass

class ConnectionRefused(Exception):
    """# `ConnectionRefused`

    Custom `Exception` returned by a `HandshakeServerSide` or `HandshakeClientSide`, communicating
    that the connection that the client side tried to enstabilish has beed refused.
    """

    pass

class HandshakeClosing(Exception):
    """# `HandshakeClosing`

    Custom `Exception` returned by a `HandshakeServerSide` or `HandshakeClientSide`, communicating
    that there were no errors but the server still needs to be shutdown, for exemple becouse the administrator decided so.
    """
    pass


# Custom Exceptions API Misusage
ABSTRACT_METHOD = "Error: APIMisusage: You are using an abstract method without a default implementation."


class APIMisusage(Exception):
    pass


# Server Messages
ACCEPTED = "$ACCEPTED$"
KICKED = "$KICKED$"
REFUSED = "$REFUSED"
REC_ERROR = "$ERROR$"
NICK_TAKEN = "$NICK_TAKEN$"
NICK_NOT_ALPHA_NUM = "$NOT_ALPHA_NUM$"
NICK_TOO_SHORT = "$NICK_TOO_SHORT$"
NICK_TOO_LONG = "$NICK_TOO_LONG$"
SHUTDOWN = "$SHUTDOWN$"
MALFORMED_PACKET = "$MALFORMED_PACKET"
