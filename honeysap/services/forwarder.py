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
from gevent.lock import BoundedSemaphore
from gevent.pool import Pool
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

    @property
    def max_connections(self):
        return int(self.config.get("max_connections", 32))

    def setup_server(self):
        super(ForwarderService, self).setup_server()

        # Create an event for stopping the handle loop
        self.stopped = gEvent()
        self.workers = Pool(self.max_connections)
        self.connection_slots = BoundedSemaphore(self.max_connections)
        self.connections = set()

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
            while not self.stopped.is_set():
                try:
                    client, client_address = self.listener.ins.accept()
                except socket.error:
                    if self.stopped.is_set():
                        break
                    raise
                if not self.connection_slots.acquire(blocking=False):
                    self.logger.warning("Forwarder connection limit reached")
                    client.close()
                    continue
                self.workers.spawn(self._handle_client, client, client_address)

    def stop(self):
        # Set the event as stopped
        self.stopped.set()
        if hasattr(self, "listener"):
            self.listener.close()
        for client, remote in list(self.connections):
            client.close()
            remote.close()
        if hasattr(self, "workers"):
            self.workers.join(timeout=2)

    def _handle_client(self, client, client_address, release_slot=True):
        remote = None
        try:
            remote, session = self.create_remote(client_address,
                                                 self.target_address,
                                                 self.target_port)
            self.connections.add((client, remote))
            while not self.stopped.is_set():
                self.handle(remote, client, client_address, session)
        except socket.error:
            pass
        finally:
            if remote is not None:
                self.connections.discard((client, remote))
                remote.close()
            client.close()
            if release_slot:
                self.connection_slots.release()

    def create_remote(self, client_address, host, port, route_context=None):
        # Creates a session for registering the events
        (client_ip, client_port) = client_address
        route_context = route_context or {}
        session = self.session_manager.get_session(
            "forwarder", client_ip, client_port, self.target_address,
            self.target_port,
            campaign_uuid=route_context.get("campaign_uuid"),
            parent_session_uuid=route_context.get("parent_session_uuid"))

        self.logger.debug("Connecting client %s:%s to remote %s:%d" % (client_ip,
                                                                       client_port,
                                                                       host, port))
        # Creates a remote socket
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            remote.connect((host, port))
        except socket.error:
            remote.close()
            raise

        session.add_event("Connected to target", data={"target_host": host,
                                                        "target_port": port})
        # Wrap it into a StreamSocket so both remote and client are
        # StreamSockets
        return StreamSocket(remote), session

    def handle_virtual(self, client, client_address, route_context=None):

        if not self.connection_slots.acquire(blocking=False):
            self.logger.warning("Forwarder connection limit reached")
            client.close()
            return

        # Connects with the target
        try:
            remote, session = self.create_remote(client_address,
                                                 self.target_address,
                                                 self.target_port, route_context)
            self.connections.add((client, remote))
            # Handle the messages until the service is stopped
            while not self.stopped.is_set():
                self.handle(remote, client, client_address, session)
        except socket.error:
            pass
        finally:
            if 'remote' in locals():
                self.connections.discard((client, remote))
                remote.close()
            self.connection_slots.release()

    def handle(self, server, client, client_address, session):
        # Simple select bag with client and server sockets
        r, __, __ = select([client, server], [], [], 0.5)
        if client in r:
            self.recv_send(client, server, session, request=True)
        if server in r:
            self.recv_send(server, client, session, request=False)

    def recv_send(self, local, remote, session, request):

        # Receive data from the local peer
        data = bytes(local.recv(self.mtu))

        # If we received zero bytes, the connection got down, raise the
        # exception so we can exit the loop and accept other clients
        if len(data) == 0:
            raise socket.error((100, "Underlying stream socket tore down"))

        # Record the event
        event = Event("Forwarding packet",
                      data={"target_host": self.target_address,
                            "target_port": self.target_port})

        # Add the entire packet to the event
        if request:
            event.request = data
        else:
            event.response = data

        # Register the event
        session.add_event(event)

        # Send it to the remote peer
        getattr(remote, "outs", remote).sendall(data)
