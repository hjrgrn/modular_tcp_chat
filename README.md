# Modular TCP Chat



## Description

Explorative project written for practicing concepts like encryption, object oriented design patterns, threading and others.
The application is incomplete, it presents a lot of bugs and vulnerabilities, is written in a non conventional way and without following conventional standards, don't use it in a production environment.
The modularity is given by the fact that some of functionalities of the chat are written using the strategy design pattern and so can they be easily changed.


## Notes

I decided to write the functions/methods that can fail in a suis generis way: instead of raising an exception they return an exception,
this way I'm able to propagate the error on the caller function without a try/except and also is clear the subtype of the exception that
the function may return from the signature.


## Dependencies

It is suggested to use a virtual environment:
Install `venv`:
```bash
# On Ubuntu based systems
sudo apt install python3-venv
```


## Installation

The provided configuration files will run the application on the local machine.

On Ubuntu 24.04 based OSes:

```bash
git clone 'https://github.com/hjrgrn/modular_tcp_chat.git'
cd modular_tcp_chat
# Create a virtual environment(suggested)
python3.12 -m venv <PATH_TO_ENV>
source <PATH_TO_ENV>/bin/activate
pip install --upgrade pip
# Without [neovim] if you don't use neovim
pip install -e .[neovim]
```


## Usage

run the server:
```bash
server
```
run the client
```bash
client
```


## Configuration

Exemplar configurations can be found in
```bash
<ROOT_DIRECTORY>/ServerConfiguration.json
# and
<ROOT_DIRECTORY>/ClientConfiguration.json
```

