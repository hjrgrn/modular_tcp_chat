import logging
import os
import sys
import sqlite3
import hashlib
import queue
import threading
from lib.auxiliaries import read_from_stdin
from lib.constants import (
    ABSTRACT_METHOD,
    ACCEPTED,
    MAX_TRIES_REACHED,
    NICK_NOT_ALPHA_NUM,
    NICK_TAKEN,
    NICK_TOO_LONG,
    NICK_TOO_SHORT,
    REFUSED,
    ConnectionRefused,
    HandshakeClosing,
    HandshakeError,
)
from lib.strategies.handlers import SocketHandler
from server.strategies.basic_authentication.auxiliaries import (
    CheckForAdmin,
    CreateAdminInteractively,
    CreateDatabase,
    CriticalDatabaseError,
    DatabaseCommand,
    LoginUser,
    NonCriticalDatabaseError,
    RegisterUser,
    RemoveClient,
    Teardown,
)


class Client:
    """# Client
    The objects produced by this class represent a client connection.
    """

    def __init__(self, socket_handler: SocketHandler, nickname: str, id: int):
        self.id = id
        self.socket_handler = socket_handler
        self.nickname = nickname


class HandshakeServerSide:
    """# HandshakeServerSide
    Abstract class for the Strategy design pattern.
    The objects produced by this class allow the server
    to perform a handshake with its clients.
    Coherent `HandshakeClientSide` and `HandshakeServerSide` strategies need
    to be written in order for the application to work.
    """

    def __init__(self, parent_ref):
        # Reference to the `Master` instance that is parent to
        # the instance of `HandshakeServerSide`
        self.parent_ref = parent_ref

    def setup(self) -> None | HandshakeError | HandshakeClosing:
        """# `setup`
        This methods needs to be called by the server in order to
        set itself up, it is an abdstract method that sets up
        anything the handshake handler needs in order to work.
        On success `None` is returned, if during the setup process
        a critical error occurs `HandshakeError` is returned,
        if during the setup process it has been decided that
        the server will be shutdown but no errors occurred
        `HandshakeClosing` exception will be returned.
        A default implementation is provided.
        """
        return None

    def connect(self, __client_sock__: SocketHandler) -> Client | Exception:
        """# `connect`
        Performs the connection between the server and a foreign host
        willing to become a client of the chat.
        Returns a `Client` object or an `Exception`.
        A default implementation that always return an `Exception`
        is provided and shoudn't be used.
        """
        return HandshakeError(ABSTRACT_METHOD)

    # TODO: I don't know if this should belong here or somewhere else.
    def authenticate_msg(self, msg: bytes) -> bytes | Exception:
        """TODO: Docstring for authenticate_msg.
        Abstract method
        Provides default implementation
        Receives message, makes sure the message comes from an
        authenticated user, returns the cleaned up message or
        an Exception
        """
        return msg

    def teardown(self) -> None | Exception:
        """# `teardown`
        Abstract method.
        This function needs to be called before shutting down the server
        in order to do a cleanup.
        Default implementation is provided.
        """
        return None

    # TODO: a custom return type may be needed
    def remove_client(self, __id__: int) -> None | Exception:
        """# `remove_client`
        Abstract method.
        Some strategy may maintain an internale state reguarding
        the clients connected, this method allows to implement
        clean up logic if the strategy needs that when a client
        is removed from the server.
        Removes the client from the chat.
        Default implementation is provided.
        """
        return None


class FirstHandshakeServerSide(HandshakeServerSide):
    """# FirstHandshakeServerSide
    Concrete implementation of the class `HandshakeServerSide`,
    that uses the Strategy design pattern.
    """

    def __init__(self, parent_ref):
        super().__init__(parent_ref)

    def connect(self, socket_handler: SocketHandler) -> Client | ConnectionRefused:
        # If the server is not ultimating the procedure in
        # 30 seconds the handshake times out
        socket_handler.set_timeout(30)

        error = None

        tries = 0

        while True:
            # Max tries reached
            if tries > 5:
                length = socket_handler.send(REFUSED.encode("utf-8"))
                if not isinstance(length, int):
                    error = length
                    break
                error = ConnectionRefused(MAX_TRIES_REACHED)
                break
            tries = tries + 1

            nickname = socket_handler.receive()

            if isinstance(nickname, Exception):
                error = nickname
                break

            nickname = nickname.decode("utf-8")

            if len(nickname) > 30:
                length = socket_handler.send(NICK_TOO_LONG.encode("utf-8"))
                if not isinstance(length, int):
                    error = length
                    break
                continue
            if len(nickname) < 3:
                length = socket_handler.send(NICK_TOO_SHORT.encode("utf-8"))
                if not isinstance(length, int):
                    error = length
                    break
                continue
            if not nickname.isalnum():
                length = socket_handler.send(NICK_NOT_ALPHA_NUM.encode("utf-8"))
                if not isinstance(length, int):
                    error = length
                    break
                continue
            if nickname.lower() == "master":
                length = socket_handler.send(NICK_TAKEN.encode("utf-8"))
                if not isinstance(length, int):
                    error = length
                    break
                continue
            if not self.parent_ref.is_nickname_avaible(nickname):
                length = socket_handler.send(NICK_TAKEN.encode("utf-8"))
                if not isinstance(length, int):
                    error = length
                    break
                continue

            # accepted
            length = socket_handler.send(ACCEPTED.encode("utf-8"))
            if not isinstance(length, int):
                error = length
                continue
            break

        # reset the default timeout
        socket_handler.reset_timeout()

        # error occurred
        if error:
            socket_handler.close()
            s = str(error)
            e = ConnectionRefused(s)
            return e

        id = self.parent_ref.get_free_id()

        return Client(socket_handler=socket_handler, nickname=nickname, id=id)


class BasicAuthHandshakeSS(HandshakeServerSide):
    """# `BasicAuthHandshakeSS`
    This strategy of `HandshakeServerSide` provides functionality for registration and
    basic password authentication using a sqlite3 database, the databased is managed
    by a specific thread.
    This strategy requires a specific `handshake_config` in the config file.
    Exemplare required configuration:
    ```json
    ...
    "handshake_config": {
        "database_path": "./instance/database.sqlite",
        "database_schema_path": "./schema.sql"
    }
    ```
    where:
    - `database_path`: the path to the database file
    - `database_schema_path`: schema of the database
    This strategy makes use of a sqlite database in order to provide authentication capabilities, a dedicated thread is created in order to operate on said database.
    """

    def __init__(self, parent_ref):
        super().__init__(parent_ref)
        self._db: sqlite3.Connection = None
        # msg passing queue used to send commands to the database
        self._command_queue: queue.Queue[DatabaseCommand] = queue.Queue()
        # specific thread that handles the database
        self._database_thread: threading.Thread = None
        # semaphore that determins the shutdown
        self._teardown_event = threading.Event()

    def setup(self) -> None | HandshakeError | HandshakeClosing:
        logging.info("Setting up HandshakeServerSide.")

        self._database_thread = threading.Thread(
            target=self._database_worker, daemon=True
        )
        self._database_thread.start()

        while True:
            command = read_from_stdin(
                "Interactive configuration:\n[1]Run the server\n[2]Create a new admin account\n[3]Flush the database and generate a new one\n[0]Shutdown",
                1,
            )
            if isinstance(command, Exception):
                s = str(command)
                return HandshakeError(s)
            if command == "0":
                return HandshakeClosing(
                    "Shutting down as required...\nSee you spacecowboy."
                )
            elif command == "1":
                error = self._run_server()
                if error is not None:
                    return error
                break
            elif command == "2":
                error = self._create_admin_account()
                if error is not None:
                    return error
            elif command == "3":
                error = self._reinstanciate_database()
                if error is not None:
                    return error
            else:
                print("Unexpected command. Try again...")

    def connect(self, socket_handler: SocketHandler) -> Client | Exception:
        """TODO: Docstring for connect.
        """
        socket_handler.set_timeout(30)

        # gathering the mode
        mode = socket_handler.receive()
        nick = None
        id = None
        if isinstance(mode, Exception):
            return mode
        if mode == b"r":
            res = self._register_user(socket_handler)
        elif mode == b"l":
            res = self._login_user(socket_handler)
        else:
            _ = socket_handler.send(REFUSED.encode("utf-8"))
            return ConnectionRefused("User tried a non authorized method.")

        if isinstance(res, Exception):
            _ = socket_handler.send(REFUSED.encode("utf-8"))
            return res
        else:
            id = res[0]
            nick = res[1]

        error = socket_handler.send(ACCEPTED.encode("utf-8"))
        if isinstance(error, Exception):
            return error

        # reset the default timeout
        socket_handler.reset_timeout()

        return Client(socket_handler, nick, id)

    def teardown(self) -> None | Exception:
        res_q = queue.Queue()
        command = Teardown(res_q)
        self._command_queue.put(command)
        self._teardown_event.set()
        self._database_thread.join()
        return res_q.get()

    def remove_client(self, id: int) -> None | Exception:
        res_q = queue.Queue()
        command = RemoveClient(res_q, id)
        self._command_queue.put(command)
        return res_q.get()

    def _create_database(self) -> None | Exception:
        """# `_create_database`

        Creates the database based on the paths provided,
        returns `None` if everything went fine, an `Exception`
        otherwise.
        """
        logging.info("Creating a new database.")
        try:
            with open(
                self.parent_ref.configuration.handshake_config["database_schema_path"],
                "r",
            ) as var:
                self._db.executescript(var.read())
            print("Database created successfully.")
        except Exception as e:
            logging.error("Unable to create a database.")
            return e

        return None

    def _connect_to_database(self) -> None | Exception:
        """# `_connect_to_database`

        Creates a connection with the database, if the database
        does not exists it will need to be initialized after.
        Returns `None` if everything went fine, an `Exception`
        otherwise.
        """
        try:
            self._db = sqlite3.connect(
                self.parent_ref.configuration.handshake_config["database_path"],
                detect_types=sqlite3.PARSE_DECLTYPES,
            )
            self._db.row_factory = sqlite3.Row
        except sqlite3.Error as e:
            return e
        except Exception as e:
            logging.exception(e)
            return e
        return None

    def _check_database(self) -> None | Exception:
        """# `_check_database`

        Check if the database is functional(the schema is correct).
        Returns `None` if everything went fine, an `Exception` otherwise.
        """
        logging.info("Checking the schema of the database.")
        # Check the schema
        try:
            res = self._db.execute(
                "SELECT id, title FROM roles WHERE (title = 'admin')"
            ).fetchone()
            if res["id"] != 1:
                return False
            res = self._db.execute(
                "SELECT id, title FROM roles WHERE (title = 'regular')"
            ).fetchone()
            if res["id"] != 2:
                return False
            res = self._db.execute(
                "SELECT id, username, email, hash_pass, subscribed, role FROM users"
            ).fetchone()
        except:
            logging.error("Invalid database schema.")
            phrase = f"The schema of the database at position: \"{self.parent_ref.configuration.handshake_config['database_path']}\" is not correct, please remove the file in that position and relaunch the program."
            return Exception(phrase)

        # Success
        return None

    def _database_worker(self):
        """Worker that operates on a dedicated thread in order to manage the database.
        In order to request an action on the database a method needs to generate a subclass of
        `server.strategies.basic_authentication.auxiliaries.DatabaseCommand` and send
        it to the worker through BasicAuthHandshakeSS.command_queue, example:
        ```python
        self.command_queue.put(command)
        response = None
        try:
            response = res_q.get()
        except Exception as e:
            return e
        if isinstance(response, Exception):
            return response
        ```
        The worker will keep working as long as `BasicAuthHandshakeSS.teardown_event` is unset.
        """
        logging.info("Setting up the database")
        self._setup_database()
        if isinstance(self._db, Exception):
            logging.error(
                f"Critical error occurred: unable to setup the database, the server cannot continue, error:\n{self._db}"
            )
            # TODO: shutdown, rithink this
            sys.exit(1)
        while self._teardown_event.is_set() == False:
            try:
                command = self._command_queue.get(timeout=5)
                command.execute(self._db)
            except queue.Empty as e:
                continue
            except Exception as e:
                raise e

    def _setup_database(self):
        """# `setup`'s helper `_setup_database`

        Does all the operations required to setting up the database,
        On success the property `db` will be turned into a `sqlite3.Connection`
        instance, otherwise `db` will turn into an instance of `Exception`
        """

        # Check if the database exists
        database_exists = os.path.isfile(
            self.parent_ref.configuration.handshake_config["database_path"]
        )

        # Connect and check the database
        error = self._connect_to_database()
        if error is not None:
            # The file exsists but we don't have the right permissons to
            # access it or a parent directory
            logging.error(error)
            self._db = error
            return

        # If database doesn't exists
        if database_exists == False:
            print("Database doesn't exists, creating it...")
            error = self._create_database()
            if error is not None:
                phrase = f"Unable to initialize the database at position: \"{self.parent_ref.configuration.handshake_config['database_path']}\", please remove the file in that position and relaunch the program."
                logging.error(phrase)
                self._db = Exception(phrase)
                return
        else:
            # Checking the schema of the database
            error = self._check_database()
            if error is not None:
                logging.error(error)
                self._db = error

    def _register_user(
        self, socket_handler: SocketHandler
    ) -> tuple[int, str] | ConnectionRefused:
        """# `_register_user`, `connect`'s helper
        Registers the user, returns id and username of the newly registered user
        or `Exception`.
        """
        # TODO: limitations
        error = socket_handler.receive()
        if isinstance(error, Exception):
            return error
        username = error.decode("utf-8")
        error = socket_handler.receive()
        if isinstance(error, Exception):
            return error
        email = error.decode("utf-8")
        password = socket_handler.receive()
        if isinstance(password, Exception):
            return password

        h = hashlib.sha512()
        h.update(password)
        hash_pass = h.hexdigest()

        res_q = queue.Queue()
        command = RegisterUser(res_q, username, email, hash_pass)
        self._command_queue.put(command)
        response = None
        try:
            response = res_q.get()
        except Exception as e:
            return e
        if isinstance(response, Exception):
            return e

        id = response

        return (id, username)

    def _login_user(self, socket_handler: SocketHandler) -> tuple[int, str] | Exception:
        """# `_login_user`, `connect`'s helper
        Logs in the user, returns id and username of the newly registered user
        or `Exception`.
        """
        error = socket_handler.receive()
        if isinstance(error, Exception):
            return error
        username = error.decode("utf-8")
        error = socket_handler.receive()
        if isinstance(error, Exception):
            return error
        email = error.decode("utf-8")
        password = socket_handler.receive()
        if isinstance(password, Exception):
            return password

        h = hashlib.sha512()
        h.update(password)
        hash_pass = h.hexdigest()

        res_q = queue.Queue()
        command = LoginUser(res_q, username, email, hash_pass)
        self._command_queue.put(command)
        response = None
        try:
            response = res_q.get()
        except Exception as e:
            return e
        if isinstance(response, Exception):
            return response

        id = response

        return (id, username)

    def _run_server(self) -> None | HandshakeError:
        """# `_run_server`, `setup`'s helper
        On success `None` is returned, otherwise a `HandshakeError`.
        """
        res_q = queue.Queue()
        command = CheckForAdmin(res_q)
        self._command_queue.put(command)
        response = None
        try:
            response = res_q.get()
        except Exception as e:
            return HandshakeError(e.__str__())
        if isinstance(response, CriticalDatabaseError):
            return HandshakeError(f"Critical database error encountered:\n{response}")
        if isinstance(response, NonCriticalDatabaseError):
            res = read_from_stdin(
                "Currently there are no admin account, do you want to create one?(y/N)",
                1,
            )
            if isinstance(res, Exception):
                return HandshakeError(res.__str__())
            if res.lower() == "y":
                logging.info("Creating an admin account.")
                res_q = queue.Queue()
                command = CreateAdminInteractively(res_q)
                self._command_queue.put(command)
                response = res_q.get()
                if isinstance(response, Exception):
                    return HandshakeError(response.__str__())
        return None

    def _create_admin_account(self) -> None | HandshakeError:
        """# `_create_admin_account`, `setup`'s helper
        On success `None` is returned, otherwise a `HandshakeError`.
        """
        logging.info("Creating an admin account.")
        res_q = queue.Queue()
        command = CreateAdminInteractively(res_q)
        self._command_queue.put(command)
        response = None
        try:
            response = res_q.get()
        except Exception as e:
            return HandshakeError(e.__str__())
        if isinstance(response, NonCriticalDatabaseError):
            logging.warning(f"Failed to create an admin account:\n{response}")
        if isinstance(response, CriticalDatabaseError):
            return HandshakeError(response.__str__())
        if response is None:
            logging.info("Admin account created correctly.")
        return None

    def _reinstanciate_database(self) -> None | HandshakeError:
        """# `_reinstanciate_database`, `setup`'s helper
        On success `None` is returned, otherwise a `HandshakeError`.
        """
        prompt = f"Every data present in the database in \"{self.parent_ref.configuration.handshake_config['database_path']}\" will be erased, do you want to procede?(y, N)"
        command = read_from_stdin(prompt, 1)
        if not isinstance(command, str):
            return command
        if command.lower() == "y":
            logging.info("Creating a new database.")
            path = self.parent_ref.configuration.handshake_config[
                "database_schema_path"
            ]
            res_q = queue.Queue()
            command = CreateDatabase(res_q, path)
            self._command_queue.put(command)
            response = None
            try:
                response = res_q.get()
            except Exception as e:
                return HandshakeError(e.__str__())
            if isinstance(response, Exception):
                return HandshakeError(response.__str__())
        else:
            print("Aborting as required.")
        return None
