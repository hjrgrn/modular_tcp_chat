import logging
import signal
import sys

from lib.constants import HandshakeClosing
from lib.strategies.handlers import EncryptSocketHandler
from server.config import ServerConfiguration
from server.server_lib import Master
from server.strategies.handshakes import BasicAuthHandshakeSS
from server.strategies.encryption import SymAsymEncHandSS


MASTER: Master = None


def run():
    """Runs the server."""
    configuration = ServerConfiguration()
    error = configuration.parse()
    if error is not None:
        print("Server cannot countinue to operate, shutting down.", file=sys.stderr)
        sys.exit(1)

    # setup server
    signal.signal(signal.SIGINT, sig_int_handler)
    global MASTER
    MASTER = Master(
        BasicAuthHandshakeSS,
        EncryptSocketHandler,
        SymAsymEncHandSS,
        configuration,
    )
    error = MASTER.run()
    if isinstance(error, HandshakeClosing):
        logging.info(error)
    if error is not None:
        logging.error(f"Uanble to run the server becouse of: {error}")


def sig_int_handler(__signum__, __frame__):
    """This function handles a SIGINT"""
    # TODO: integrare i thread
    global MASTER
    logging.info("Shutting down...")
    MASTER.graceful_shutdown()
