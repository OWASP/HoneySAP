# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# Author:
#   Martin Gallo (@martingalloar)
#   Code contributed by SecureAuth to the OWASP CBAS project
#

# Standard imports
import socket
# External imports
from gevent.event import Event as gEvent
from gevent.select import select
from scapy.supersocket import StreamSocket
# Custom imports
from honeysap.core.event import Event
from honeysap.core.service import BaseService


class ForwarderService(BaseService):
    """The ForwarderService implements a HoneySAP service that forwards traffic
    to a target host/port. It can be used to easily integrate HoneySAP with
    other honeypots or actual services running on other hosts. By running it as
    a virtual service it's possible also to use it for forwarding internally
    routed traffic to external services running on the same or other hosts.


    Example configuration for a Kippo SSH honeypot directly exposed to the
    HoneySAP listener address::

        # Service configuration
        -
            service: ForwarderService
            alias: LocalSSHService

            enabled: yes

            listener_port: 22

            target_port: 2222
            target_address: 127.0.0.1


    Example configuration for an internal Kippo SSH honeypot running as a
    virtual service::

        # Service configuration
        -
            service: ForwarderService
            alias: InternalKippoService

            enabled: yes
            virtual: yes

            listener_port: 22
            listener_address: 10.0.0.2

            target_port: 22
            target_address: 127.0.0.1

        # SAPRouter route table
        - action: allow
          mode: raw
          target: 10.0.0.2
          port: 22
          password:

    In this scenario is possible to provide access to a Kippo honeypot running
    on the local machine, through the SAPRouter service.

    """

    #: The IP address of the target host the traffic should be forwarded to.
    @property
    def target_address(self):
        return self.config.get("target_address")

    #: The target port the traffic should be forwarded to.
    @property
    def target_port(self):
        return self.config.get("target_port")

    #: The backlog for the listener
    @property
    def backlog(self):
        return self.config.get("backlog", 5)

    #: The MTU to use when receiving and sending packets
    @property
    def mtu(self):
        return self.config.get("mtu", 2048)

    def setup_server(self):
        super(ForwarderService, self).setup_server()

        # Create an event for stopping the handle loop
        self.stopped = gEvent()

        # Create and bind the listener socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # If the server is not virtual, bind and listen to the
        # specified address/port
        if not self.virtual:
            sock.bind((self.listener_address, self.listener_port))
            sock.listen(self.backlog)
            self.listener = StreamSocket(sock)

    def run(self):
        # If is not virtual, wait until a client connection arrives
        if not self.virtual:

            try:
                while not self.stopped.is_set():
                    # Connects with the client
                    (client, client_address) = self.listener.ins.accept()

                    # Connects with the target
                    remote = self.create_remote(client_address,
                                                self.target_address,
                                                self.target_port)

                    # Handle the messages until the service is stopped
                    try:
                        while not self.stopped.is_set():
                            self.handle(remote, client, client_address)
                    # If a socket error was raised, we should continue
                    # to allow other connections
                    except socket.error as e:
                        continue

            # Other exceptions should be raised
            except Exception as e:
                raise e

    def stop(self):
        # Set the event as stopped
        self.stopped.set()

    def create_remote(self, client_address, host, port):
        # Creates a session for registering the events
        (client_ip, client_port) = client_address
        self.session = self.session_manager.get_session("forwarder",
                                                        client_ip,
                                                        client_port,
                                                        self.target_address,
                                                        self.target_port)

        self.logger.debug("Connecting client %s:%s to remote %s:%d" % (client_ip,
                                                                       client_port,
                                                                       host, port))
        # Creates a remote socket
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect((host, port))

        self.session.add_event("Connected to target", data={"target_host": host,
                                                            "target_port": port})
        # Wrap it into a StreamSocket so both remote and client are
        # StreamSockets
        return StreamSocket(remote)

    def handle_virtual(self, client, client_address):

        # Connects with the target
        remote = self.create_remote(client_address,
                                    self.target_address,
                                    self.target_port)

        # Handle the messages until the service is stopped
        try:
            while not self.stopped.is_set():
                self.handle(remote, client, client_address)
        except:
            pass

    def handle(self, server, client, client_address):
        # Simple select bag with client and server sockets
        r, __, __ = select([client, server], [], [], 0.5)
        if client in r:
            self.recv_send(client, server, request=True)
        if server in r:
            self.recv_send(server, client, request=False)

    def recv_send(self, local, remote, request):

        # Receive data from the local peer
        data = local.recv(self.mtu)

        # If we received zero bytes, the connection got down, raise the
        # exception so we can exit the loop and accept other clients
        if len(data) == 0:
            raise socket.error((100, "Underlying stream socket tore down"))

        # Record the event
        event = Event("Forwarding packet",
                      data={"target_host": self.target_address,
                            "target_port": self.target_port})

        # Add the entire packet to the event
        data = str(data)
        if request:
            event.request = data
        else:
            event.response = data

        # Register the event
        self.session.add_event(event)

        # Send it to the remote peer
        remote.send(data)
