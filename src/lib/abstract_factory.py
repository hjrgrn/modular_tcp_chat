# TODOFIRST:
from lib.strategies import FirstSocketHandler, SocketHandler


class AbstractFactory:

    """Docstring for AbstractFactory. """

    def __init__(self):
        self.index = 0

    def initialize_factory(self, index: int):
        """TODO: Docstring for initialize_factory.
        :returns: TODO

        """
        self.index = index

    def create_socket_handler(self):
        """TODO: Docstring for create_socket_handler.
        :returns: TODO

        """
        if self.index == 0:
            return SocketHandler
        if self.index == 1:
            return FirstSocketHandler
