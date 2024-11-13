from client.client_lib import ChatClient
from client.config import ClientConfiguration
from client.strategies.handshakes import BasicAuthHandshakeCS
from client.strategies.encryption import SymAsymEncHandCL
import signal
import sys

from lib.strategies.handlers import EncryptSocketHandler


MASTER: ChatClient = None


def run():
    """
    Runs the client.
    """
    # TODO: logging
    configuration = ClientConfiguration()
    error = configuration.parse()
    if error is not None:
        # TODO: improve this
        sys.exit(1)

    signal.signal(signal.SIGINT, sig_int_handler)

    global MASTER
    MASTER = ChatClient(
        BasicAuthHandshakeCS, SymAsymEncHandCL, EncryptSocketHandler, configuration
    )
    MASTER.run()


def sig_int_handler(__signum__, __frame__):
    """This function handles a SIGINT"""
    # TODO: rethink this
    global MASTER
    MASTER.graceful_shutdown()
    sys.exit(0)
