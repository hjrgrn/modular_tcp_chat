"""
A collection of auxiliary functions and structs for the `HandshakeServerSide` strategy `BasicAuthHandshakeSS`
"""

import getpass
import hashlib
import logging
import queue
import random
import sqlite3
import string

from lib.auxiliaries import read_from_stdin


class CriticalDatabaseError(Exception):
    """
    An exception that indicates that the database cannot continue.
    """

    pass


class NonCriticalDatabaseError(Exception):
    """
    An exception that indicates that the database can continue despite it.
    """

    pass


class DatabaseCommand:
    """# `DatabaseCommand`:
    In order for `BasicAuthHandshakeSS` to communicate with it's own worker thread that manages the database, a subinstance `DatabaseCommand` needs to be generated.
    The programmer needs to generate a `queue.Queue` and pass it to a subclass of `DatabaseCommand`, enqueue the command on `BasicAuthHandshakeSS.command_queue`
    and wait for a response to be pushed on that same queue, example:
    ```python
    # Inside a method of `BasicAuthHandshakeSS`
    res_q = queue.Queue()
    command = CreateAdminInteractively(res_q)
    self.command_queue.put(command)
    response = res_q.get()
    if isinstance(response, Exception):
        return HandshakeError(response.__str__())

    ```
    The worker `BasicAuthHandshakeSS._database_worker` calls `execute` method on the `DatabaseCommand` that receives, `execute` method will add the response to the queue provided.
    An eventual value that needs to be used by `BasicAuthHandshakeSS` will be pushed on the queue, or `None`; if something went wrong an `Exception` will be pushed, we have two type of specific `Exception`: `CriticalDatabaseError` and `NonCriticalDatabaseError`.
    This abstract class provides default implementations, but they are useless.
    Loggin can be handled inside the commands.
    """

    def __init__(self, response_queue: queue.Queue):
        self.response_queue: queue.Queue = response_queue

    def execute(self, __db__: sqlite3.Connection):
        self.response_queue.put(None)


class CheckForAdmin(DatabaseCommand):
    def execute(self, db: sqlite3.Connection):
        """
        Checks if there is an admin account.
        If no admin is found a `NonCriticalDatabaseError` will be pushed on the queue,
        if a critical error was encountered a `CreateDatabase` will be pushed,
        otherwise `None`.
        """
        try:
            admin_role = db.execute(
                "SELECT id FROM roles WHERE (title = 'admin')"
            ).fetchone()["id"]
            admin = db.execute(
                "SELECT id FROM users WHERE (role = ?)", (admin_role,)
            ).fetchone()
            if admin is None:
                self.response_queue.put(NonCriticalDatabaseError("No admin accounts"))
                return
        except sqlite3.Error as e:
            logging.error(f"Critical database error encountered:\n{e}")
            self.response_queue.put(CriticalDatabaseError(e.__str__()))
            return
        except Exception as e:
            logging.error(f"Critical unexpected database error encountered:\n{e}")
            logging.exception(e)
            self.response_queue.put(CriticalDatabaseError(e.__str__()))
            return
        self.response_queue.put(None)


class CreateAdminInteractively(DatabaseCommand):
    def execute(self, db: sqlite3.Connection):
        """
        Creates an admin interactively by asking information to the user through stdin.
        `None` is enqueued if the admin was create successfully, an `Exception` otherwise.
        """
        logging.info("Creating an admin interactively.")

        username = read_from_stdin("Username: ", 60)
        if not isinstance(username, str):
            self.response_queue.put(username)
            return
        email = read_from_stdin("Email: ", 200)
        if not isinstance(email, str):
            self.response_queue.put(email)
            return
        error = check_unicity_account(db, username, email)
        if error is not None:
            self.response_queue.put(error)
            return
        try:
            password = getpass.getpass("Password: ")
            confirm_pass = getpass.getpass("Confirm password: ")
        except (EOFError, getpass.GetPassWarning) as e:
            logging.error(
                f"Critical error: Unable to create an admin account, error: {e}"
            )
            self.response_queue.put(CriticalDatabaseError(e.__str__()))
            return
        except Exception as e:
            # Unexpected behaviour
            logging.error(
                f"Critical error: Unable to create an admin account, error: {e}"
            )
            logging.exception(e)
            self.response_queue.put(CriticalDatabaseError(e.__str__()))
            return
        if password != confirm_pass:
            logging.info(
                "Non critical error: Unable to create an admin account becouse of a user error."
            )
            self.response_queue.put(
                NonCriticalDatabaseError("You provided 2 different passwords")
            )
            return

        key = "".join(random.choices(string.ascii_letters, k=10))

        # hashing password
        hashing = hashlib.sha512()
        hashing.update((password + key).encode("utf-8"))
        hash_pass = hashing.hexdigest()

        # database registration
        try:
            role = db.execute(
                "SELECT id FROM roles WHERE (title = 'admin')"
            ).fetchone()["id"]
            db.execute(
                "INSERT INTO users (username, email, hash_pass, key, role, logged_in) VALUES (?, ?, ?, ?, ?, 0)",
                (username, email, hash_pass, key, role),
            )
            db.commit()
        except (sqlite3.Error, TypeError) as e:
            logging.error(
                f"Critical error: Unable to create an admin account, error: {e}"
            )
            self.response_queue.put(CriticalDatabaseError(e.__str__()))
            return
        except Exception as e:
            # unexpected behaviour
            logging.error(
                f"Critical error: Unable to create an admin account, error: {e}"
            )
            self.response_queue.put(CriticalDatabaseError(e.__str__()))
            return

        logging.info("Admin account create successfully.")
        self.response_queue.put(None)


class CreateDatabase(DatabaseCommand):
    def __init__(self, response_queue: queue.Queue, path: str):
        """
        Initializes a database, an additional argument is required in the constructor compared to `DatabaseCommand`, `path`; the `path` argument will be the path used to create the database.
        """
        # TODO: we need to think about the path variable, maybe we can do a custom
        # object to pass to `DatabaseCommand` that has response_queue and database_schema_path
        # inside of it
        super().__init__(response_queue)
        self.path = path

    def execute(self, db: sqlite3.Connection):
        """
        Initializes a database, enqueues `None` if everything went fine, an `Exception` otherwise
        """
        logging.info("Creating a new database.")
        try:
            with open(
                self.path,
                "r",
            ) as var:
                db.executescript(var.read())
            logging.info("Database created successfully.")
        except sqlite3.Error as e:
            logging.error(
                f"Critical error: unable to create the database, exception:\n{e}"
            )
            self.response_queue.put(CriticalDatabaseError(e.__str__()))
            return
        except Exception as e:
            logging.error(
                f"Critical error: unable to create the database, exception:\n{e}"
            )
            logging.exception(e)
            self.response_queue.put(CriticalDatabaseError(e.__str__()))
            return

        self.response_queue.put(None)


class RemoveClient(DatabaseCommand):
    def __init__(self, response_queue: queue.Queue, id: int):
        """
        Removes a client, needs an additionl argument in the constructor, the id of the client to be removed.
        """
        # TODO: we need to think about the path variable, maybe we can do a custom
        # object to pass to `DatabaseCommand` that has response_queue and database_schema_path
        # inside of it
        super().__init__(response_queue)
        self.id = id

    def execute(self, db: sqlite3.Connection):
        """
        Removes a client, enqueues `None` in case of success, an exception otherwise.
        """
        logging.info("Removing a client from the database.")
        try:
            db.execute("UPDATE users SET logged_in = 0 WHERE (id = ?)", (self.id,))
            db.commit()
        except sqlite3.Error as e:
            logging.error(
                f"Critical error: unable to operate on the database, exception:\n{e}"
            )
            self.response_queue.put(CriticalDatabaseError(e.__str__()))
            return
        except Exception as e:
            logging.error(
                f"Critical error: unable to operate on the database, exception:\n{e}"
            )
            self.response_queue.put(CriticalDatabaseError(e.__str__()))
            return
        self.response_queue.put(None)


class Teardown(DatabaseCommand):
    def execute(self, db: sqlite3.Connection):
        """
        This command needs to be called during the graceful shutdown procedure, it turns every user as non-logged so that they can log in after the server is rebooted.
        Enqueues `None` in case of success, an exception otherwise.
        """
        logging.info("Initiatig database cleanup")
        try:
            db.execute("UPDATE users SET logged_in = 0")
            db.commit()
        except sqlite3.Error as e:
            logging.error(
                f"Critical error: unable to cleanup the database, exception:\n{e}"
            )
            self.response_queue.put(CriticalDatabaseError(e.__str__()))
            return
        except Exception as e:
            logging.error(
                f"Critical error: unable to cleanup the database, exception:\n{e}"
            )
            self.response_queue.put(CriticalDatabaseError(e.__str__()))
            return

        self.response_queue.put(None)


class RegisterUser(DatabaseCommand):
    def __init__(
        self,
        response_queue: queue.Queue,
        username: str,
        email: str,
        hash_pass: str,
        key: str,
    ):
        """
        Registers a user, it needs additional argument in the constructor:
        - nick
        - email
        - hash_pass: the hashed version of the password
        Enqueues the id of the newly registered user or an exception
        """
        super().__init__(response_queue)
        self.username = username
        self.email = email
        self.hash_pass = hash_pass
        self.key = key

    def execute(self, db: sqlite3.Connection):
        """
        Registers a user, enqueues the id of the user or an `Exception`.
        """
        logging.info("Adding a new user")
        error = check_unicity_account(db, self.username, self.email)
        if error is not None:
            self.response_queue.put(error)
            return
        try:
            db.execute(
                "INSERT INTO users (username, email, hash_pass, key) VALUES (?, ?, ?, ?)",
                (self.username, self.email, self.hash_pass, self.key),
            )
            db.commit()
            user = db.execute(
                "SELECT id FROM users WHERE (username = ?)", (self.username,)
            ).fetchone()
            id = user["id"]
        except sqlite3.Error as e:
            logging.error(
                f"Critical error: unable to operate on the database, exception:\n{e}"
            )
            self.response_queue.put(CriticalDatabaseError(e.__str__()))
            return
        except Exception as e:
            logging.error(
                f"Critical error: unable to operate on the database, exception:\n{e}"
            )
            logging.exception(e)
            self.response_queue.put(CriticalDatabaseError(e.__str__()))
            return

        logging.info("New user added successfully")
        self.response_queue.put(id)


class LoginUser(DatabaseCommand):
    def __init__(
        self, response_queue: queue.Queue, username: str, email: str, password: str
    ):
        """
        Logs a user in, it needs additional argument in the constructor:
        - nick
        - email
        - hash_pass: the hashed version of the password
        """
        super().__init__(response_queue)
        self.username = username
        self.email = email
        self.password = password

    def execute(self, db: sqlite3.Connection):
        logging.info("Loggin in a user")
        try:
            user = db.execute(
                "SELECT id, username, email, hash_pass, logged_in, key FROM users  WHERE (username = ?) AND (email = ?)",
                (self.username, self.email),
            ).fetchone()
        except sqlite3.Error as e:
            logging.error(
                f"Critical error: unable to operate on the database, exception:\n{e}"
            )
            self.response_queue.put(CriticalDatabaseError(e.__str__()))
            return
        except Exception as e:
            logging.error(
                f"Critical error: unable to operate on the database, exception:\n{e}"
            )
            self.response_queue.put(CriticalDatabaseError(e.__str__()))
            return

        if user is None:
            self.response_queue.put(NonCriticalDatabaseError("User doesn't exsists"))
            return
        if user["logged_in"] == 1:
            self.response_queue.put(NonCriticalDatabaseError("User already logged in"))
            return
        if user["email"] != self.email:
            self.response_queue.put(NonCriticalDatabaseError("Wrong email provided"))
            return

        h = hashlib.sha512()
        h.update((self.password + user["key"]).encode("utf-8"))
        hash_pass = h.hexdigest()

        if user["hash_pass"] != hash_pass:
            self.response_queue.put(NonCriticalDatabaseError("Wrong password provided"))
            return

        try:
            db.execute(
                "UPDATE users SET logged_in = 1 WHERE (username = ?) AND (email = ?) AND (hash_pass = ?)",
                (self.username, self.email, self.password),
            )
            db.commit()
        except sqlite3.Error as e:
            logging.error(
                f"Critical error: unable to operate on the database, exception:\n{e}"
            )
            self.response_queue.put(CriticalDatabaseError(e.__str__()))
            return
        except Exception as e:
            logging.error(
                f"Critical error: unable to operate on the database, exception:\n{e}"
            )
            self.response_queue.put(CriticalDatabaseError(e.__str__()))
            return

        logging.info("User logged in successfully")
        self.response_queue.put(user["id"])


def check_unicity_account(
    db: sqlite3.Connection, username: str, email: str
) -> None | CriticalDatabaseError | NonCriticalDatabaseError:
    """#`check_unicity_account`

    Helper function that check for the unicity of username and email,
    if username or email have already been taken a `NonCriticalDatabaseError`
    will be returned, if there were problem accessing the database a
    `CriticalDatabaseError` will be returned, if username and email
    haven't already been registered `None` is returned.
    """
    try:
        exsisting = db.execute(
            "SELECT id FROM users WHERE (username = ?)", (username,)
        ).fetchone()
        if exsisting is not None:
            return NonCriticalDatabaseError("Username provided is already taken")
        exsisting = db.execute(
            "SELECT id FROM users WHERE (email = ?)", (email,)
        ).fetchone()
        if exsisting is not None:
            return NonCriticalDatabaseError("Username provided is already taken")
    except sqlite3.Error as e:
        logging.error(f"Critical error: Unable to create an admin account, error:\n{e}")
        return CriticalDatabaseError(e.__str__())
    except Exception as e:
        # unexpected behaviour
        logging.error(f"Critical error: Unable to create an admin account, error:\n{e}")
        return CriticalDatabaseError(e.__str__())
    return None
