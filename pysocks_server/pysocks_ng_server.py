#!/usr/bin/env python3

import logging
import select
import socket
import struct
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler

from pysocks_ng_server_constants import *
from pysocks_ng_server_errors import *

logging.basicConfig(level=logging.DEBUG)

# Code sucks, and is that a dragon?

# TODO move config to file
# AUTH levels: 0 is no auth, 2 is username password

config = {
    "AUTH":0
}


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class SocksProxy(StreamRequestHandler):

    def handle(self):
        logging.info('Accepting connection from %s:%s'%(self.client_address))

        # Get the version(\x05) and the number of methods provided
        version = self.connection.recv(1)
        nmethods = struct.unpack(">B", self.connection.recv(1))[0]
        
        if version != SOCKS5_VER:
            # raise SOCKS5AuthError("Client is not using an socks5 compliant client, got version %s from %s:%s during initial auth"%(version.decode(), self.client_address))

            logging.fatal("Client is not using an socks5 compliant client, got version %s from %s:%s during initial auth"%(version.decode(), self.client_address))

        # Weird issue on my machine, this fixes it

        if nmethods not in range(1,256):
            logging.fatal("Client sent out of range nmethod %i from %s:%s"%(methods, self.client_address))

        # Get available methods
        methods = self._get_available_methods(nmethods)

        # Check if NO AUTH is asked by client and if we support it

        if config["AUTH"] == 0 and 0 in methods:
            
            # Tell client our version and chosen method
            self.connection.sendall(SOCKS5_VER + NO_AUTH)
            logging.info("Accepting empty auth from %s:%s"%(self.client_address))

        else:

            # We don't accept any authentication methods
            self.server.close_request(self.request)
            return

        # Now we continue the exchange

        self._continue_exchange()
        

        self.server.close_request(self.request)

    # Just saw a dragon, stay safe everyone

    def _continue_exchange(self):

        # print(self.connection.recv(4))
        version = self.connection.recv(1)

        if version != SOCKS5_VER:
            # raise SOCKS5AuthError("Client is not using an socks5 compliant client, got version %s from %s:%s during request phase"%(version.decode(), self.client_address))

            logging.fatal("Client is not using an socks5 compliant client, got version %s from %s:%s during request phase"%(version.decode(), self.client_address))
        
        cmd, _, address_type = struct.unpack("!BBB", self.connection.recv(3))

        if address_type == 1:  
            # We got an IPv4 request
            
            address = socket.inet_ntop(socket.AF_INET, self.connection.recv(4))
        
        elif address_type == 3:  
            # We got an domain name request
        
            # b"\xFF"[0] is 255 what is this magic
            # Copied it from stack overflow can't find it again

            domain_length = self.connection.recv(1)[0]
            domain = self.connection.recv(domain_length)

        elif address_type == 4:
            # We got an IPv6 request

            address = socket.inet_ntop(socket.AF_INET6, self.connection.recv(16))         

        # Now we get the ports
        port = struct.unpack('!H', self.connection.recv(2))[0]

        # And we build the address(es) information

        if "domain" in locals():
            address_infos = socket.getaddrinfo(domain, port, 0, socket.SOCK_STREAM)
        else:
            address_infos = socket.getaddrinfo(address, port, 0, socket.SOCK_STREAM)

        # reply

        if cmd == 1:
            # Client sent CONNECT code

            remote, bind_address = self._try_all_address(address_infos)
            
        else:
            # We don't support the cmd sent by client

            self.server.close_request(self.request)


        if remote == "" and bind_address == "":
            # Tell client remote refused connection
            # We will just give back what they gave us in this case

            if "domain" in locals():

                reply = self.generate_reply(REPLY_CONNECTION_REFUSED, address_type, port = port, domain = domain, domain_length = domain_length)
            else:

                reply = self.generate_reply(REPLY_CONNECTION_REFUSED, address_type, address = address, port = port)

            self.connection.sendall(reply)
            self.server.close_request(self.request)


        # Now we tell the client the good news (that we connected successfully)

        if remote.family == socket.AF_INET6:
            address_type = 4

        elif remote.family == socket.AF_INET:
            address_type = 1

        else:
            logging.fatal("Unknown family type")
            self.server.close_request(self.request)

        reply = self._generate_reply(REPLY_SUCCESS, address_type, address = address, port = port)
        self.connection.sendall(reply)

        # establish data exchange
        if cmd == 1:
            logging.debug("Starting exchange")
            self._exchange_loop(self.connection, remote)

    def _try_all_address(self, address_infos):
        for address_info in address_infos:
            
            sock_family, sock_type, _, _, sock_addr = address_info
            bind_address = sock_addr

            # Format it into IPv4 format

            if sock_family == socket.AF_INET6:
                address, port, _, _ = bind_address
                bind_address = (address, port)

            try:
                
                remote = socket.socket(sock_family, sock_type)
                remote.connect(sock_addr)

                if sock_family == socket.AF_INET6:

                    logging.info('Connected to [%s]:%s' % (address, port))
                else:

                    logging.info('Connected to %s:%s' % (address, port))

                return remote, bind_address

            except Exception as e:

                if sock_family == socket.AF_INET6:

                    logging.info('Failed to connect to [%s]:%s' % (address, port))
                else:

                    logging.info('Failed to connect to %s:%s' % (address, port))
        
        logging.error("We have exhausted all address options for client %s:%s"%(self.client_address))
        return ("", "")

    def _get_available_methods(self, n):

        # I don't like this...
        # This gets methods like b"\x02\x00" and returns a list like [2, 0]
        
        methods = self.connection.recv(n)
        methods = list(methods)

        return methods

    def _verify_credentials(self):
        version = ord(self.connection.recv(1)) # struct.unpack(">B", buf.read(1))[0]
        assert version == 1

        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len).decode('utf-8')

        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode('utf-8')

        if username == self.username and password == self.password:
            # success, status = 0
            response = struct.pack("!BB", version, 0)
            self.connection.sendall(response)
            return True

        # failure, status != 0
        response = struct.pack("!BB", version, 0xFF)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False

    def _generate_reply(self, status_code, address_type, address="", port = 0, domain = 0, domain_length = 0):
            
            if address_type == 1:
                # It's an IPv4

                encoded_addr = socket.inet_pton(socket.AF_INET, address)
        
            elif address_type == 3:  
                # It's an domain
            
                encoded_addr = struct.pack("!B", domain_length) + domain

            elif address_type == 4:
                # It's an IPv6

                encoded_addr = socket.inet_pton(socket.AF_INET6, address)

            encoded_port = struct.pack('!H', port)
            reply = SOCKS5_VER + status_code + b"\x00" + struct.pack("!B",address_type) + encoded_addr + encoded_port

            return reply

    def _exchange_loop(self, client, remote):

        while True:

            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(4096)
                print(data)
                if remote.send(data) <= 0:
                    break

            if remote in r:
                data = remote.recv(4096)
                print(data)
                if client.send(data) <= 0:
                    break

logging.info("Simple SOCKS5 server serving on 127.0.0.1:1080")


if __name__ == '__main__':
    try:
        with ThreadingTCPServer(('127.0.0.1', 1080), SocksProxy) as server:
            server.serve_forever()
    
    except KeyboardInterrupt:
        logging.info("Received keyboard interrupt, shutting down")
        server.server_close()