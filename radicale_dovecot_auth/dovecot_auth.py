# Dovecot authentication plugin for Radicale.
# Copyright (C) 2017-2019 Arvedui <arvedui@posteo.de>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from base64 import b64encode
import os
import socket
import sys
import getopt
import getpass


PRINT_CMDS_RESP = False
HANDSHAKE = "VERSION\t1\t1\nCPID\t{}\n"
SUPPORTED_MAJOR_VERSION = 1
AUTH_COMMAND = "AUTH\t{id}\tPLAIN\tservice={service}\tresp="


class DovecotAuthException(Exception):
    """DovecotAuth base Exception"""


class UnsupportedVersion(DovecotAuthException):
    """Thrown if the protocol version of the auth server ist not supported"""


class HandshakeFailed(DovecotAuthException):
    """Thrown if the Handshake with the auth server fails"""


class UnexpectedData(DovecotAuthException):
    """
    Thrown if there is still data the recieve buffer that was not expected
    """


class DovecotAuth:
    """
    DovecotAuth provides authentication against a Dovecot authentication
    service using the PLAIN mechanism.

    Only version 1.1 as described in the `Dovecot Wiki`_

    .. _Dovecot Wiki: https://wiki2.dovecot.org/Design/AuthProtocol

    :param service: Name of the service authentication services are provided for
    :param socket_path: Path to the unix domain socket of the auth server
    :param host: hostname of the auth server
    :param port: port of the auth server
    """

    def __init__(self, service, *, socket_path=None, host=None, port=None):
        self.socket_path = socket_path
        self.buffer = bytes()
        self.authid = 1
        self.service = service

        if socket_path:
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.socket.connect(socket_path)

        elif host and port:
            self.socket = socket.create_connection((host, port))

        else:
            raise RuntimeError(
                "auth_socket path or auth_host and auth_port must be set"
            )

        self._handshake()

    def buffer_is_empty(self):
        return len(self.buffer) == 0

    def _readline(self):
        """Read one line from the socket using a receive buffer"""

        nextlineend = self.buffer.find(b"\n")
        while nextlineend == -1:
            self.buffer += self.socket.recv(4096)

            nextlineend = self.buffer.find(b"\n")

        nextline = self.buffer[:nextlineend]
        self.buffer = self.buffer[nextlineend + 1 :]
        return nextline.split(b"\t")

    def _send(self, msg):
        """
        Send data via the socket

        :param msg: message to send
        """

        send_bytes = 0

        while send_bytes != len(msg):
            send_bytes += self.socket.send(msg[send_bytes:])

    def _handshake(self):
        """
        Perform handshake according to dovecot auth protocol
        """

        done = False
        plain = False
        handshake = HANDSHAKE.format(os.getpid()).encode("utf8")
        if PRINT_CMDS_RESP:
            print("Sending handshake: {}".format(handshake))
        self._send(handshake)
        while not done:
            command, *arguments = self._readline()
            if PRINT_CMDS_RESP:
                print("Handshake resp: {}".format(command))
                print("          args: {}".format(arguments))
            if command == b"VERSION":
                if int(arguments[0]) != SUPPORTED_MAJOR_VERSION:
                    raise UnsupportedVersion

            elif command == b"MECH":
                if arguments[0] == b"PLAIN":
                    plain = True

            elif command == b"DONE":
                done = True

        if not plain:
            raise HandshakeFailed("auth mechanism PLAIN is not supported by dovecot")

    def authenticate(self, username, password):
        """Authenticate given credentials"""
        credentials = "\0{username}\0{password}".format(
            username=username, password=password
        )
        credentials = b64encode(credentials.encode("utf8"))

        command = AUTH_COMMAND.format(id=self.authid, service=self.service)
        command = command.encode("ascii")
        command += credentials
        command += b"\n"

        self.authid += 1
        if PRINT_CMDS_RESP:
            print("Sending Auth: {}".format(command))
        self._send(command)

        command, *arguments = self._readline()
        if PRINT_CMDS_RESP:
            print("Auth resp: {}".format(command))
            print("     args: {}".format(arguments))
        if not self.buffer_is_empty:
            raise UnexpectedData(
                "Server has sent data that was not expected: {}".format(self.buffer)
            )

        if command == b"OK":
            return True
        return False


def main():
    username = None
    password = None
    unix_socket = None
    host = None
    port = None

    opts, _ = getopt.getopt(
        sys.argv[1:], "u:P:s:h:p:", ["user=", "password=", "socket=", "host=", "port="]
    )
    for opt, arg in opts:
        if opt in ("-u", "--user"):
            username = arg
        elif opt in ("-P", "--password"):
            password = arg
        elif opt in ("-s", "--socket"):
            unix_socket = arg
        elif opt in ("-h", "--host"):
            host = arg
        elif opt in ("-p", "--port"):
            port = arg

    if username is None or (unix_socket is None and (host is None or port is None)):
        print("Missing arguments")
        print("dovecot_auth.py -u username (Required)")
        print("                -P password (Optional - will be prompted at runtime)")
        print("  Unix socket:")
        print("                -s socket path")
        print("  TCP connection:")
        print("                -h host ip")
        print("                -p tcp port")
        exit(1)

    if password is None:
        password = getpass.getpass()

    kwargs = dict()
    kwargs["socket_path"] = unix_socket
    kwargs["host"] = host
    kwargs["port"] = port
    conn = DovecotAuth("test-app", **kwargs)
    if conn.authenticate(username, password):
        print("Success")
    else:
        print("Fail")


if __name__ == "__main__":
    main()
