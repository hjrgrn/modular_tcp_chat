import sys


def read_from_stdin(prompt: str, max_amount: int) -> str | Exception:
    """# `read_from_stdin`

    Reads from stdin one character at the time considering the maximum amount
    of characters provided, if the amount is exceeded an `Exception` is returned.
    """
    print(prompt)
    word = ""
    while True:
        c = sys.stdin.read(1)
        if c == "\n":
            break
        word = word + c
        if len(word) > max_amount:
            return Exception("Word provided is too long.")
    return word
