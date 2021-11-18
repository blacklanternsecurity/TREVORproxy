# NOTE: Adapted from https://github.com/rushter/socks5

import select
import socket
import struct
import logging
import traceback
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler

log = logging.getLogger('trevorproxy.socks')
SOCKS_VERSION = 5


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    
    def __init__(self, *args, **kwargs):

        self.username = kwargs.pop('username', '')
        self.password = kwargs.pop('password', '')
        self.source_address_gen = kwargs.pop('source_address_gen')
        super().__init__(*args, **kwargs)


class SocksProxy(StreamRequestHandler):

    def handle(self):

        self.ip_version = 4

        log.debug('Accepting connection from %s:%s' % self.client_address)

        # greeting header
        try:

            # read and unpack 2 bytes from a client
            header = self.connection.recv(2)
            version, nmethods = struct.unpack("!BB", header)

            # socks 5
            assert version == SOCKS_VERSION
            assert nmethods > 0

            # get available methods
            methods = self.get_available_methods(nmethods)

            # accept only USERNAME/PASSWORD auth
            if 2 not in set(methods):
                # close connection
                self.server.close_request(self.request)
                return

            # send welcome message
            self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 2))

            if not self.verify_credentials():
                return

        except Exception as e:
            if log.level <= logging.DEBUG:
                e = traceback.format_exc()
            log.error(f'Error in greeting: {e}')
            return

        # request
        try:
            version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
            assert version == SOCKS_VERSION

            if address_type == 1:  # IPv4
                self.ip_version = 4
                address = socket.inet_ntop(socket.AF_INET, self.connection.recv(4))
                ip_version = 4
            if address_type == 4:  # IPv6
                address = socket.inet_ntop(socket.AF_INET6, self.connection.recv(16))
                self.ip_version = 6
            elif address_type == 3:  # Domain name
                domain_length = self.connection.recv(1)[0]
                address = self.connection.recv(domain_length)
                address = socket.gethostbyname(address)
            port = struct.unpack('!H', self.connection.recv(2))[0]

        except Exception as e:
            if log.level <= logging.DEBUG:
                e = traceback.format_exc()
            log.error(f'Error in request: {e}')
            return

        # reply
        try:
            if cmd == 1:  # CONNECT
                family = (socket.AF_INET if self.ip_version == 4 else socket.AF_INET6)
                remote = socket.socket(family, socket.SOCK_STREAM)

                random_source_addr = str(next(self.server.source_address_gen))
                log.debug(f'Using random source address: {random_source_addr}')

                # special case for IPv6
                if self.ip_version == 6:
                    remote.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)

                remote.bind((random_source_addr, 0))
                remote.connect((address, port))
                bind_address = remote.getsockname()
                log.debug(f'Connected to {address}:{port}')
            else:
                self.server.close_request(self.request)

            addr_format = ("I" if self.ip_version == 4 else "IIII")
            addr, port = bind_address[:2]
            reply = struct.pack(f"!BBBBIH", SOCKS_VERSION, 0, 0, 1, address_type, port)

        except Exception as e:
            if log.level <= logging.DEBUG:
                e = traceback.format_exc()
            log.error(f'Error in reply: {e}')
            # return connection refused error
            reply = self.generate_failed_reply(address_type, 5)
            return

        self.connection.sendall(reply)

        # establish data exchange
        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(self.connection, remote)

        self.server.close_request(self.request)


    def get_available_methods(self, n):

        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods


    def verify_credentials(self):

        valid = False

        version = ord(self.connection.recv(1))
        assert version == 1

        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len).decode('utf-8')

        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode('utf-8')

        if (username == self.server.username and password == self.server.password) or \
            (not self.server.username and not self.server.password):
            valid = True

        if valid:
            # success, status = 0
            response = struct.pack("!BB", version, 0)
            self.connection.sendall(response)
        else:
            # failure, status != 0
            response = struct.pack("!BB", version, 0xFF)
            self.connection.sendall(response)
            self.server.close_request(self.request)

        return valid


    def generate_failed_reply(self, address_type, error_number):

        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)


    def exchange_loop(self, client, remote):

        while 1:

            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(4096)
                if remote.send(data) <= 0:
                    break

            if remote in r:
                data = remote.recv(4096)
                if client.send(data) <= 0:
                    break
