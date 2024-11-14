DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS roles;

CREATE TABLE roles (
    id INTEGER PRIMARY KEY,
    title VARCHAR(20) UNIQUE NOT NULL
);

INSERT INTO roles (
    id,
    title
) VALUES (
    1,
    "admin"
);

INSERT INTO roles (
    id,
    title
) VALUES (
    2,
    "regular"
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username VARCHAR(60) UNIQUE NOT NULL,
    email VARCHAR(200) UNIQUE NOT NULL,
    hash_pass TEXT NOT NULL,
    key CHAR(10) NOT NULL,
    subscribed TIMESTAMP NOT NULL DEFAULT (CURRENT_TIMESTAMP),
    role INTEGER NOT NULL DEFAULT (
        -- we need to fix this
        -- SELECT id FROM roles WHERE (
          -- title = "regular"
        --)
        2
    ),
    logged_in INTEGER CHECK(logged_in BETWEEN 0 AND 1) DEFAULT (1),
    FOREIGN KEY (role) REFERENCES roles (id)
);

