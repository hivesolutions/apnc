#!/usr/bin/python
# -*- coding: utf-8 -*-

# Hive Apple Push Client
# Copyright (c) 2008-2016 Hive Solutions Lda.
#
# This file is part of Hive Apple Push Client.
#
# Hive Apple Push Client is free software: you can redistribute it and/or modify
# it under the terms of the Apache License as published by the Apache
# Foundation, either version 2.0 of the License, or (at your option) any
# later version.
#
# Hive Apple Push Client is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# Apache License for more details.
#
# You should have received a copy of the Apache License along with
# Hive Apple Push Client. If not, see <http://www.apache.org/licenses/>.

__author__ = "João Magalhães <joamag@hive.pt>"
""" The author(s) of the module """

__version__ = "1.0.0"
""" The version of the module """

__revision__ = "$LastChangedRevision$"
""" The revision number of the module """

__date__ = "$LastChangedDate$"
""" The last change date of the module """

__copyright__ = "Copyright (c) 2008-2016 Hive Solutions Lda."
""" The copyright for the module """

__license__ = "Apache License, Version 2.0"
""" The license for the module """

import ssl
import json
import socket
import struct
import select
import binascii

import legacy

HOST = "gateway.push.apple.com"
""" The host of the apn service to be used when
in production mode """

PORT = 2195
""" The port of the apn service to be used when
in sandbox mode """

SANDBOX_HOST = "gateway.sandbox.push.apple.com"
""" The host of the apn service to be used when
in sandbox mode """

SANDBOX_PORT = 2195
""" The port of the apn service to be used when
in sandbox mode """

KEY_FILE = "apn_key.pem"
""" The path to the (private) key file to be used
in the encrypted communication with the server """

CERT_FILE = "apn_cert.pem"
""" The path to the certificate file to be used
in the encrypted communication with the server """

DEFAULT_TOKEN_STRING = "12007EF74A0E8518EAB44CA4922B49FD4002462AFB37D7D9890A7E02D81FD24B"
""" The default token string to be used in case
none is provided, this token value should be used
as the basic identifier of the device, this also
includes the security information offered by the
process of authentication between the phone and
the apple's apn server """

def send_message(
    token_string = DEFAULT_TOKEN_STRING,
    message = "Hello World",
    sound = "default",
    badge = 0,
    sandbox = True,
    wait = False
):
    # creates the socket that will be used for the
    # communication with the remote host and
    _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _socket = ssl.wrap_socket(
        _socket,
        keyfile = KEY_FILE,
        certfile = CERT_FILE,
        server_side = False
    )

    # creates the address using the sandbox flag as reference
    # and the uses it to connect to the remote host
    address = sandbox and (SANDBOX_HOST, SANDBOX_PORT) or (HOST, PORT)
    _socket.connect(address)

    # converts the current token (in hexadecimal) to a
    # string of binary data for the message
    token = binascii.unhexlify(token_string)

    # creates the message structure using with the
    # message (string) as the alert and then converts
    # it into a json format (payload)
    message_s = dict(
       aps = dict(
            alert = message,
            sound = sound,
            badge = badge
        )
    )
    payload = json.dumps(message_s)

    # verifies if the generated payload in unicode based
    # if that's the case encodes it sing the default encoding
    is_unicode = type(payload) == legacy.UNICODE
    if is_unicode: payload = payload.encode("utf-8")

    # sets the command with the zero value (simplified)
    # then calculates the token and payload lengths
    command = 0
    token_length = len(token)
    payload_length = len(payload)

    # creates the initial template for message creation by
    # using the token and the payload length for it, then
    # applies the various components of the message and packs
    # them according to the generated template
    template = "!BH%dsH%ds" % (token_length, payload_length)
    message = struct.pack(template, command, token_length, token, payload_length, payload)
    _socket.send(message)

    # sets the current socket in non blocking mode and then
    # runs the select operation in it to check if there's read
    # data available for reading
    _socket.setblocking(0)
    ready = wait and select.select([_socket], [], [], 3.0) or ((), (), ())

    # in case there are socket with read data available
    # must read it in the proper way, otherwise sets the
    # data string with an empty value
    if ready[0]: data = _socket.recv(4096)
    else: data = b""

    # closes the socket (nothing more left to be don
    # for this notification)
    _socket.close()

    # prints the response to the just sent request value
    # this should be an empty string in case everything
    # went fine with the request
    print("Response: '%s'" % data)

if __name__ == "__main__":
    send_message()
