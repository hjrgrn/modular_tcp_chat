import argparse
import json
import logging
from lib.constants import ClientConfigurationError


class ClientConfiguration:
    """
    # Usage
    Generate an instance, call parse on that instance, pass the instance to `ChatClient`
    as `configuration` parameter.
    """

    def __init__(self):
        self.address: str = None
        self.port: int = None
        self.max_word_size: int = None
        self.recoverable_errors = []
        self.unrecoverable_errors = []

    def parse(self) -> None | ClientConfigurationError:
        """# `parse`
        This method parses cli arguments and the configuration file.
        Returns `None` if everything went fine or a `ClientConfigurationError` if unrecoverable errors
        have been found.
        """
        self._parsing_configuration_file()
        self._parsing_cli_args()

        if self.max_word_size is None:
            self.max_word_size = 4096
        if self.address is None:
            self.unrecoverable_errors.append(
                ClientConfigurationError(
                    "Expected address in the configuration file or in the cli arguments."
                )
            )
        if self.port is None:
            self.unrecoverable_errors.append(
                ClientConfigurationError(
                    "Expected port number in the configuration file or in the cli arguments."
                )
            )

        for e in self.recoverable_errors:
            logging.warning(
                f"Recoverable error encountered during the parsing of the configuration:\n{e}\n"
            )

        found_error = False
        for e in self.unrecoverable_errors:
            found_error = True
            logging.error(f"Unrecoverable error:\n{e}\n")
        if found_error:
            return ClientConfigurationError("Found unrecoverable error/s")

        return None

    def _parsing_configuration_file(self):
        """Parses the configuration file, if any, updates multiple instance variables."""
        with open("./ClientConfiguration.json", "r") as var:
            raw_config = var.read()
            try:
                json_config = json.loads(raw_config)
                self.address = json_config.get("address", None)
                self.port = json_config.get("port", None)
                self.max_word_size = json_config.get("max_word_size", None)
            except (
                json.JSONDecodeError,
                AttributeError,
                PermissionError,
                FileNotFoundError,
            ) as e:
                self.recoverable_errors.append(e)
            except Exception as e:
                self.recoverable_errors.append(e)

        return None

    def _parsing_cli_args(self):
        """Parses CLI arguments, if any, updates multiple instance variables."""
        # Parsing CLI arguments
        parser = argparse.ArgumentParser()
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

        args = parser.parse_args()
        if args.addr is not None:
            self.address = args.addr
        if args.port is not None:
            self.port = args.port
        if args.max_word_size is not None:
            self.max_word_size = args.max_word_size
