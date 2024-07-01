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

from radicale.auth import BaseAuth
from radicale import logger
from radicale_dovecot_auth.dovecot_auth import DovecotAuth
from contextlib import suppress


SERVICE = "radicale"


class Auth(BaseAuth):
    """Authenticate user with dovecot auth service.

    Configuration:

    [auth]
    type = radicale_dovecot_auth

    auth_socket = path_to_socket

    # or tcp based
    host = example.com
    port = 10000
    """

    def login(self, login, password):
        kwargs = dict()

        with suppress(KeyError):
            kwargs["socket_path"] = self.configuration.get("auth", "auth_socket")
        with suppress(KeyError):
            kwargs["host"] = self.configuration.get("auth", "auth_host")
            kwargs["port"] = self.configuration.get("auth", "auth_port")

        if "socket_path" in kwargs:
            if "host" and "port" in kwargs:
                logger.warning(
                    "dovecot_auth ambiguous configuration: both socket and TCP configuration present"
                )
            logger.info(
                "dovecot_auth using unix socket {}".format(kwargs["socket_path"])
            )
        elif "host" and "port" in kwargs:
            logger.info(
                "dovecot_auth using TCP socket {}:{}".format(
                    kwargs["host"], kwargs["port"]
                )
            )
        else:
            raise RuntimeError(
                "auth_socket path or auth_host and auth_port must be set"
            )

        auth = DovecotAuth(SERVICE, **kwargs)
        return login if auth.authenticate(login, password) else ""
