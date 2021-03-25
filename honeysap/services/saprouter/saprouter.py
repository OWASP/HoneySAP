# ===========
# HoneySAP - SAP low-interaction honeypot
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# The library was designed and developed by Martin Gallo from
# the SecureAuth's Innovation Labs team.
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
# ==============

# Standard imports
from datetime import datetime
# External imports
from scapy.packet import Raw
from scapy.utils import hexdump
from scapy.supersocket import StreamSocket

from gevent.timeout import Timeout

from pysap.SAPNI import SAPNIServerThreaded, SAPNIServerHandler, SAPNIClient
from pysap.SAPRouter import (SAPRouter, SAPRouterError, SAPRouterInfoClient,
                             router_is_control, router_is_admin,
                             router_is_known_type, router_control_opcodes,
                             router_adm_commands, router_return_codes,
                             router_is_route, SAPRouterInfoServer)
# Custom imports
from honeysap.core.logger import Loggeable
from honeysap.core.service import BaseTCPService

from .routetable import RouteTable


def unix_time(dt):
    return (dt - datetime(1970, 1, 1)).total_seconds()


class SAPRouterClient(Loggeable, SAPNIClient):

    ni_version = None

    id = 0
    address = None
    partner = None
    service = None
    target_service = None
    talk_mode = None

    routed = False
    traced = False
    connected = False

    connected_on = None


class SAPRouterServerHandler(Loggeable, SAPNIServerHandler):

    @property
    def hostname(self):
        return self.config.get("hostname", "sapnw702")

    @property
    def release(self):
        return self.config.get("release", 721)

    @property
    def router_version(self):
        return self.config.get("router_version", 40)

    @property
    def router_version_patch(self):
        return self.config.get("router_version_patch", 4)

    @property
    def info_password(self):
        return self.config.get("info_password", None)

    @property
    def external_admin(self):
        return self.config.get("external_admin", False)

    @property
    def timeout(self):
        return self.config.get("timeout", 5)

    @property
    def route_table_filename(self):
        return self.config.get("route_table_filename", "saprouttab")

    @property
    def route_table_working_directory(self):
        return self.config.get("route_table_working_directory", "/usr/sap/router")

    @property
    def time_started(self):
        return self.server.time_started

    @property
    def pid(self):
        return self.server.pid

    @property
    def parent_pid(self):
        return self.config.get("parent_pid", 0)

    @property
    def parent_port(self):
        return self.config.get("parent_pid", 0)

    def __init__(self, request, client_address, server):
        """Initialization"""
        self.config = server.config
        client_ip, client_port = client_address
        server_ip, server_port = server.server_address
        self.session = server.session_manager.get_session("saprouter",
                                                          client_ip,
                                                          client_port,
                                                          server_ip,
                                                          server_port)
        SAPNIServerHandler.__init__(self, request, client_address, server)

    def setup(self):
        """Add the client to the current client lists"""
        SAPNIServerHandler.setup(self)
        self.server.clients_count += 1
        self.server.clients[self.client_address].id = self.server.clients_count
        self.server.clients[self.client_address].address = self.client_address[0]
        self.server.clients[self.client_address].connected_on = datetime.today()

    def finish(self):
        """Closes the connection and deletes the client from the clients list"""
        self.close()
        SAPNIServerHandler.finish(self)

    def handle(self):
        """Handle data from the client. Treat timeouts inside the handle method"""

        # Set the timeout
        self._timeout = Timeout(self.timeout)
        self._timeout.start()

        # Try to handle the request
        try:
            while not self.closed.is_set():
                # Check if the current client was already routed to a target service
                if self.server.clients[self.client_address].routed:
                    # In that case we should treat the request as routed,
                    # and do not handle further packets from this client
                    self.handle_routed()
                    break

                else:
                    # Otherwise, we should expect for a route request within the timeout
                    # defined. Receive and store the packet
                    self.packet = self.request.recv()
                    # Pass the control to the handle_data function
                    self.handle_data()

        except Timeout as t:
            # If this is another timeout, raise it so another block can
            # catch it
            if t is not self._timeout:
                raise t
            self.handle_timeout()

        finally:
            self._timeout.cancel()

    def handle_data(self):
        """Handles a received packet"""
        self.session.add_event("Received packet", request=str(self.packet))

        if SAPRouter not in self.packet or not router_is_known_type(self.packet):
            self.logger.debug("Invalid packet sent to SAPRouter")

        router = self.packet[SAPRouter]
        if router_is_route(router):
            return self.handle_route(router)
        elif router_is_control(router):
            return self.handle_control(router)
        elif router_is_admin(router):
            return self.handle_admin(router)

    def handle_routed(self):
        """Handles a packet for an already routed client."""
        self.logger.debug("Handling routed message")

        # We create a new raw StreamSocket for passing it to the virtual
        # service. The SAP router service should take care of the NI layer
        # and perform the reassembling, keep alive, etc.
        stream_socket = StreamSocket(self.request.ins)

        # Now handle the virtual service, from now on the virtual service
        # would take care of this client
        self.server.clients[self.client_address].target_service.handle_virtual(stream_socket,
                                                                               self.client_address)

    def handle_route(self, pkt):
        """Handles route messages"""
        self.logger.debug("Handling route message")
        # Perform some checks on the route request
        if self.check_route(pkt):
            # Route the request
            self.route_request(pkt)

    def check_route(self, pkt):
        """Checks if a route request is valid.
        """

        # Check the route NI version
        if pkt.route_ni_version > self.router_version:
            self.logger.debug("Route request version greater")
            # TODO: Check if we need to return an error

        # Cehck the number of routes
        if len(pkt.route_string) <= 0:
            self.logger.debug("Invalid number of routes in route request")
            # TODO: Check if we need to return an error

        # Check the number of entries
        if pkt.route_entries < 2 and pkt.route_entries != len(pkt.route_string):
            self.logger.debug("Invalid number of entries in route request")
            # TODO: Check if we need to return an error

        # Check the number of remaining entries
        if pkt.route_rest_nodes >= pkt.route_entries:
            self.logger.debug("Invalid route rest nodes number")
            # TODO: Check if we need to return an error

        # Check the offset value against the length
        if pkt.route_offset >= pkt.route_length:
            self.logger.debug("Invalid route string offset")
            # TODO: Check if we need to return an error

        # Check the offset value against the remaining hops
        actual_offset = sum([len(x) for x in pkt.route_string[:pkt.route_rest_nodes]])
        if pkt.route_offset != actual_offset:
            self.logger.debug("Invalid route string offset")
            # TODO: Check if we need to return an error

        # Check that the first hop is the SAP Router
        first_hop = pkt.route_string[0]
        if first_hop.hostname != self.server.listener_address or \
           first_hop.port != self.server.listener_port:
            self.logger.debug("Invalid first hop in route string")
            # TODO: Check if we need to return an error

        return True

    def route_request(self, pkt):
        """Perform a lookup on the route table and routes the packet accordingly
        if allowed.
        """
        route_string = pkt.route_string[pkt.route_rest_nodes]
        (action, talk_mode, password) = self.server.route_table.lookup_target(route_string.hostname,
                                                                              int(route_string.port))

        if action == RouteTable.ROUTE_DENY:
            self.logger.debug("Route to %s:%s denied" % (route_string.hostname,
                                                         route_string.port))
            self.return_error(return_code=-94,
                              error="%s: route permission denied (%s to %s, %s)" % (self.hostname,
                                                                                    self.server.listener_address,
                                                                                    route_string.hostname,
                                                                                    route_string.port))
            return

        elif talk_mode != RouteTable.MODE_ANY and talk_mode != pkt.route_talk_mode:
            self.logger.debug("Talk mode (%d) to %s:%s denied" % (pkt.route_talk_mode,
                                                                  route_string.hostname,
                                                                  route_string.port))
            self.return_error(return_code=2)  # TODO: Return the proper error
            return

        elif action == RouteTable.ROUTE_ALLOW:
            if password:
                if password == route_string.password:
                    self.logger.debug("Valid password for route to %s:%s" % (route_string.hostname,
                                                                             route_string.port))
                    self.session.add_event("Route request allowed, valid password", data={"target_host": route_string.hostname,
                                                                                          "target_port": route_string.port,
                                                                                          "password": route_string.password},
                                           request=str(pkt))

                else:
                    self.logger.debug("Invalid password for route to %s:%s" % (route_string.hostname,
                                                                               route_string.port))
                    self.session.add_event("Route request allowed, invalid password", data={"target_host": route_string.hostname,
                                                                                            "target_port": route_string.port,
                                                                                            "password": route_string.password},
                                           request=str(pkt))
                    self.return_error(return_code=3)  # TODO: Return the proper error
                    return

            else:
                self.logger.debug("Route request allowed to %s:%s" % (route_string.hostname,
                                                                      route_string.port))
                self.session.add_event("Route request allowed", data={"target": route_string.hostname,
                                                                      "port": route_string.port,
                                                                      "password": route_string.password},
                                       request=str(pkt))

        # The route is accepted, now look the service for the target address/port
        # and register it as routed
        service = self.server.service_manager.find_service_by_address(route_string.hostname,
                                                                      int(route_string.port))

        # If the service wasn't found, we should return a timeout message,
        # meaning that the SAP Router tried to connect to the target service
        # but it didn't responded
        if service is None:
            self.logger.debug("Target service %s:%s not available" % (route_string.hostname,
                                                                      route_string.port))
            self.session.add_event("Target service not available", data={"target": route_string.hostname,
                                                                         "port": route_string.port,
                                                                         "password": route_string.password},
                                   request=str(pkt))

        else:
            self.logger.debug("Target service %s:%s found, registering and routing" % (route_string.hostname,
                                                                                       route_string.port))

            # First cancel the timeout as a valid route was specified
            self._timeout.cancel()

            # Register the current client as routed and set the target
            # address, port and service
            self.server.clients[self.client_address].routed = True
            self.server.clients[self.client_address].connected = True
            self.server.clients[self.client_address].target_service = service
            self.server.clients[self.client_address].talk_mode = pkt.route_talk_mode
            self.server.clients[self.client_address].partner = route_string.hostname
            self.server.clients[self.client_address].service = int(route_string.port)

            # Send a PONG message to notify the client the route was accepted
            self.request.send(SAPRouter(type=SAPRouter.SAPROUTER_PONG))

    def handle_control(self, pkt):
        """Handles control messages"""
        opcode_str = router_control_opcodes[pkt.opcode] if pkt.opcode in router_control_opcodes else "unknown"
        self.logger.debug("Handling control message, opcode %d (%s)",
                          pkt.opcode, opcode_str)
        # Version request
        if pkt.opcode == 1:
            self.logger.debug("Received version request (client version %d)", pkt.version)
            self.server.clients[self.client_address].ni_version = pkt.version
            self.request.send(SAPRouter(type=SAPRouter.SAPROUTER_CONTROL,
                                        version=self.router_version,
                                        opcode=2,
                                        return_code=-13))
        else:
            self.logger.debug("Unhandled opcode %d (%s)",
                              pkt.opcode, opcode_str)
            return self.return_error(return_code=-13,
                                     error="invalid client version",
                                     detail="NiBufIProcMsg: unknown opcode 3 received")

    def handle_admin(self, pkt):
        """Handles admin messages"""
        self.logger.debug("Handling admin message, command %d (%s)",
                          pkt.adm_command,
                          router_adm_commands[pkt.adm_command])

        if not self.external_admin:
            self.logger.debug("External administration disabled")
            return self.return_error(return_code=-94,
                                     error="Admin from remote denied")

        # Information request
        if pkt.adm_command == 2:
            self.logger.debug("Received information request (password %s)", pkt.adm_password)

            # If a password was specified but doesn't match, return error
            if self.info_password and self.info_password != pkt.adm_password.strip("\x00"):
                self.session.add_event("Information request invalid password", data=pkt.adm_password, request=str(self.packet))
                return self.return_error(return_code=-94,
                                         error="route denied")
            else:
                self.session.add_event("Information request valid password", data=pkt.adm_password, request=str(self.packet))
                return self.return_info()

        # Trace connection request
        if pkt.adm_command == 12:
            self.logger.debug("Received trace connection request (# clients: %s)", pkt.adm_client_count)

            for client_id in pkt.adm_client_ids:
                for client in self.server.clients:
                    if self.server.clients[client].id == client_id:
                        self.server.clients[client].traced = True
                return

        self.logger.debug("Unhandled command %d (%s)",
                          pkt.adm_command,
                          router_adm_commands[pkt.adm_command])

    def handle_timeout(self):
        """Handles timeout"""
        self.logger.debug("Timed out client")
        self.return_error(return_code=-5,
                          error="connection timed out",
                          detail="RTPENDLIST::timeoutPend: no route received within %ds (CONNECTED)" % self.timeout)

    def return_info(self):
        """Returns an information request response"""
        self.logger.debug("Returning information request")

        info_clients = []
        for client in list(self.server.clients.values()):
            info_client = SAPRouterInfoClient(id=client.id)
            info_client.address = client.address
            if client.routed:
                info_client.partner = client.partner
                info_client.service = client.service
            info_client.connected_on = unix_time(client.connected_on)

            info_client.flag_traced = client.traced
            info_client.flag_routed = client.routed
            info_client.flag_connected = client.connected

            info_clients.append(info_client)

        info_clients = "".join([str(client) for client in info_clients])
        info_pkt = Raw(info_clients)
        self.request.send(info_pkt)
        self.session.add_event("Returned information request", response=str(info_pkt))

        __, server_port = self.server.server_address

        info_pkt = SAPRouterInfoServer(pid=self.pid,
                                       ppid=self.parent_pid,
                                       started_on=unix_time(self.time_started),
                                       port=server_port,
                                       pport=self.parent_port)
        hexdump(info_pkt)
        self.request.send(info_pkt)
        self.session.add_event("Returned information request", data={"packet": "info_packet"},
                               response=str(info_pkt))

        info_pkt = Raw("Total no. of clients: %d\x00" % len(self.server.clients))
        self.request.send(info_pkt)
        self.session.add_event("Returned information request", data={"packet": "total_no_clients"},
                               response=str(info_pkt))

        info_pkt = Raw("Working directory   : %s\x00" % self.route_table_working_directory)
        self.request.send(info_pkt)
        self.session.add_event("Returned information request", data={"packet": "working_directory"},
                               response=str(info_pkt))

        info_pkt = Raw("Routtab             : %s\x00" % self.route_table_filename)
        self.request.send(info_pkt)
        self.session.add_event("Returned information request", data={"packet": "routtab"},
                               response=str(info_pkt))

        self.request.close()

    def return_error(self, **options):
        """Returns an error response"""
        self.logger.debug("Returning error code %d (%s)", options.get("return_code"),
                          router_return_codes[options.get("return_code")])

        error_text = SAPRouterError(release=str(self.release),
                                    version=str(self.router_version),
                                    error_time=datetime.now().strftime(SAPRouterError.time_format),
                                    location="SAPRouter %d.%d on '%s'" % (self.router_version,
                                                                          self.router_version_patch,
                                                                          self.hostname))
        for field in list(options.keys()):
            setattr(error_text, field, options[field])

        error_pkt = SAPRouter(type=SAPRouter.SAPROUTER_ERROR,
                              version=self.router_version,
                              opcode=0,
                              return_code=options.get("return_code"),
                              err_text_value=error_text)
        self.request.send(error_pkt)
        self.session.add_event("Returned error",
                               data={"return_code": options.get("return_code"),
                                     "error_msg": router_return_codes[options.get("return_code")]},
                               response=str(error_pkt))


class SAPRouterServerThreaded(Loggeable, SAPNIServerThreaded):

    clients_cls = SAPRouterClient
    clients_count = 0

    def __init__(self, server_address, RequestHandlerClass,
                 bind_and_activate=False, socket_cls=None, keep_alive=True,
                 base_cls=SAPRouter):
        """Initialization of the SAP Router threaded server"""
        SAPNIServerThreaded.__init__(self, server_address, RequestHandlerClass,
                                     bind_and_activate, socket_cls, keep_alive,
                                     base_cls=base_cls)


class SAPRouterService(BaseTCPService):

    server_cls = SAPRouterServerThreaded
    handler_cls = SAPRouterServerHandler

    def setup_server(self):
        super(SAPRouterService, self).setup_server()
        self.server.route_table = RouteTable(self.config.get("route_table", None))
        self.server.listener_port = self.listener_port
        self.server.listener_address = self.listener_address
        # Generates a random pid and records the time when the service started
        self.server.pid = self.server.config.get("pid", None)
        self.server.time_started = self.server.config.get("time_started", datetime.today())
