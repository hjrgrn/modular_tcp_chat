import argparse
import logging
import json

from lib.constants import ServerConfigurationError


class ServerConfiguration:
    """
    Class representing the configuration of the server application.
    Exemplar configuration found in `<root directory>/ServerConfiguration.json`
    ```json
    {
        "log": "INFO",
        "production": false,
        "address": "127.0.0.1",
        "port": 5000,
        "max_word_size": 4096,
        "max_clients": 32,
        "handshake_config": {}
    }
    ```
    """

    def __init__(self):
        # Instance variables
        # NOTE: configuration passed as argument through the Cli
        # Take precedence over configuration passed through the
        # configuration file
        self.recoverable_errors = []
        self.unrecoverable_errors = []
        self.log_level = None
        self.production = None
        self.address = None
        self.port = None
        self.max_word_size = None
        self.max_clients = None
        self.handshake_config = {}

    def parse(self) -> None | ServerConfigurationError:
        """# `parse`
        This method parses cli arguments and the configuration file.
        Returns `None` if everything went fine or a `ServerConfigurationError`
        if unrecoverable errors have been found.
        This method needs to be called after creating an instance.
        """
        self._parsing_configuration_file()
        self._parsing_cli_args()

        if self.log_level is None:
            self.log_level = logging.INFO
        if self.production is None:
            self.production = False
        if self.max_clients is None:
            self.max_clients = 32
        if self.max_word_size is None:
            self.max_word_size = 4096
        if self.address is None:
            self.unrecoverable_errors.append(
                ServerConfigurationError(
                    "Expected address in the configuration file or in the cli arguments."
                )
            )
        if self.port is None:
            self.unrecoverable_errors.append(
                ServerConfigurationError(
                    "Expected port number in the configuration file or in the cli arguments."
                )
            )

        # Configuring log level
        logging.basicConfig(
            format="%(asctime)s\n\x1b[35;1mSERVER\x1b[0m\x1b[34m:\x1b[0m \x1b[33m%(levelname)s\x1b[0m\x1b[34m:\x1b[0m %(message)s",
            level=self.log_level,
        )

        # Logs eventual recoverable errors
        for e in self.recoverable_errors:
            logging.warning(
                f"Recoverable error encountered during the parsing of the configuration:\n{e}\n"
            )

        # Logs eventual unrecoverable errors and returns
        # an Exception if any have been found
        found_error = False
        for e in self.unrecoverable_errors:
            found_error = True
            logging.error(f"Unrecoverable error:\n{e}\n")
        if found_error:
            return ServerConfigurationError("Found unrecoverable error/s")

        return None

    def _parse_log_level(self, log_level: str | None):
        """Parses the log level provided, if any.
        Updates the `log_level` instance variable.
        """
        if log_level is not None:
            log_level = log_level.upper().strip()
            if log_level == "DEBUG":
                self.log_level = logging.DEBUG
            elif log_level == "INFO":
                self.log_level = logging.INFO
            elif log_level == "WARNING":
                self.log_level = logging.WARNING
            elif log_level == "ERROR":
                self.log_level = logging.ERROR
            elif log_level == "CRITICAL":
                self.log_level = logging.CRITICAL
            else:
                self.recoverable_error["prase_log_level"] = ServerConfigurationError(
                    "Unable to parse the logging level."
                )

    def _parsing_configuration_file(self):
        """Parses the configuration file, if any, updates multiple instance variables."""
        # Parsing configuration file
        with open("./ServerConfiguration.json", "r") as var:
            raw_config = var.read()
            try:
                json_config = json.loads(raw_config)
                log_level = json_config.get("log", None)
                self._parse_log_level(log_level)
                self.production = json_config.get("production", None)
                self.address = json_config.get("address", None)
                self.port = json_config.get("port", None)
                self.max_word_size = json_config.get("max_word_size", None)
                self.max_clients = json_config.get("max_clients", None)
                handshake_config: dict = json_config.get("handshake_config", None)
                if handshake_config:
                    for k, v in handshake_config.items():
                        self.handshake_config[k] = v
            except (
                json.JSONDecodeError,
                AttributeError,
                PermissionError,
                FileNotFoundError,
            ) as e:
                self.recoverable_errors.append(e)
            except Exception as e:
                self.recoverable_errors.append(e)

    def _parsing_cli_args(self):
        """Parses CLI arguments, if any, updates multiple instance variables."""
        # Parsing CLI arguments
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "-l",
            "--log",
            type=str,
            help="Decide what logging level to use.\nDefault: INFO\nPossible values: DEBUG, INFO, WARNING, ERROR, CRITICAL",
        )
        parser.add_argument(
            "-a",
            "--addr",
            type=str,
            help="Provide the address to which the server will be bound to.",
        )
        parser.add_argument(
            "-p",
            "--port",
            type=int,
            help="Provide the port number that the server is going to use.",
        )
        parser.add_argument(
            "-w",
            "--max_word_size",
            type=int,
            help="Provide the maximum word size(read documentation for more informations), default is 4096",
        )
        parser.add_argument(
            "-c",
            "--max_clients",
            type=int,
            help="Provide the maximum amount of clients avaible at the same moment, default is 32",
        )
        args = parser.parse_args()
        self._parse_log_level(args.log)
        if args.addr is not None:
            self.address = args.addr
        if args.port is not None:
            self.port = args.port
        if args.max_word_size is not None:
            self.max_word_size = args.max_word_size
        if args.max_clients is not None:
            self.max_clients = args.max_clients
