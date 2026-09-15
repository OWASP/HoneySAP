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
from datetime import datetime
from ipaddress import ip_address
from string import Template
# External imports
from scapy.packet import Raw
from scapy.utils import hexdump
from scapy.supersocket import StreamSocket

from gevent.timeout import Timeout

from pysap.SAPNI import (SAPNI, SAPNIStreamSocket, SAPNIServerThreaded,
                         SAPNIServerHandler, SAPNIClient)
from pysap.SAPRouter import (SAPRouter, SAPRouterError, SAPRouterInfoClient,
                             ROUTER_TALK_MODE_NI_MSG_IO,
                             router_is_control, router_is_admin,
                             router_is_known_type, router_control_opcodes,
                             router_adm_commands, router_return_codes,
                             router_is_route, SAPRouterInfoServer)
# Custom imports
from honeysap.core.logger import Loggeable
from honeysap.core.service import BaseTCPService

from .routetable import RouteTable
from .error_profiles import (resolve_error_profile, render_error_options)


def unix_time(dt):
    return int((dt - datetime(1970, 1, 1)).total_seconds())


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
        return int(self.config.get("release", 916))

    @property
    def router_version(self):
        return int(self.config.get("router_version", 40))

    @property
    def router_version_patch(self):
        return int(self.config.get("router_version_patch",
                                   7 if self.release == 916 else 4))

    @property
    def error_profile(self):
        return getattr(self.server, "error_profile", None) or resolve_error_profile(
            self.release, self.config.get("error_profile", None))

    @property
    def partner_name_mode(self):
        return self.config.get("partner_name_mode",
                               self.error_profile["partner_name_mode"])

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

        # Scapy raises EOFError for a clean peer close. Older installed pysap
        # releases do not consume it in virtual NI handlers, so the router
        # must also treat it as a normal routed-client disconnect.
        except (OSError, EOFError):
            self.logger.debug("Client %s disconnected", self.client_address)

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

        packet_length = (len(bytes(self.packet.payload)) if SAPNI in self.packet
                         else len(bytes(self.packet)))
        limit = self.error_profile["max_request_length"]
        if limit is not None and packet_length > limit:
            self.logger.debug("Oversized SAPRouter request (%d bytes)", packet_length)
            self.session.add_event("Invalid SAPRouter packet")
            self.close()
            return

        if SAPRouter not in self.packet or not router_is_known_type(self.packet):
            self.logger.debug("Invalid packet sent to SAPRouter")
            self.session.add_event("Invalid SAPRouter packet")
            if self.error_profile["unknown_packet_error"]:
                self.emit_profile_error("route_expected")
            return

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
        client = self.server.clients[self.client_address]
        target = client.target_service
        if client.talk_mode == ROUTER_TALK_MODE_NI_MSG_IO:
            # The virtual NI service must receive complete framed packets,
            # decoded using its own protocol instead of SAPRouter.
            stream_socket = SAPNIStreamSocket(self.request.ins,
                                              keep_alive=target.server.keep_alive,
                                              base_cls=target.server.base_cls,
                                              timeout=self.request.timeout,
                                              max_frame_length=self.request.max_frame_length)
        else:
            # Native talk mode intentionally bypasses NI framing.
            stream_socket = StreamSocket(self.request.ins,
                                         target.server.base_cls or Raw)
        target.handle_virtual(stream_socket, self.client_address)

    def handle_route(self, pkt):
        """Handles route messages"""
        self.logger.debug("Handling route message")
        # Perform some checks on the route request
        if self.check_route(pkt):
            # Route the request
            self.route_request(pkt)

    def check_route(self, pkt):
        """Reject malformed route metadata before destination lookup.

        The default line values are observed on SAPRouter 9.16-100.
        """
        hops = pkt.route_string or []
        if pkt.route_length and not hops:
            return self.invalid_route("missing_route_bytes")
        if hops and (sum(len(hop) for hop in hops) != pkt.route_length or
                     len(bytes(pkt.payload)) > 0):
            return self.invalid_route("bad_length")
        if not hops:
            return self.invalid_route("no_hops")
        if pkt.route_entries < 2 or pkt.route_entries != len(hops):
            return self.invalid_route("bad_entries")
        if pkt.route_rest_nodes >= pkt.route_entries:
            return self.invalid_route("bad_rest")
        actual_offset = sum(len(hop) for hop in hops[:pkt.route_rest_nodes])
        if (pkt.route_offset >= pkt.route_length or
                pkt.route_offset != actual_offset):
            return self.invalid_route("bad_offset")
        if pkt.route_ni_version == 0:
            self.emit_profile_error("route_version_old",
                                    route_ni_version=pkt.route_ni_version)
            return False
        return True

    def invalid_route(self, reason):
        """Send an invalid-route error and stop routing."""
        self.emit_profile_error("invalid_route", reason=reason)
        return False

    def route_request(self, pkt):
        """Perform a lookup on the route table and routes the packet accordingly
        if allowed.
        """
        route_string = pkt.route_string[pkt.route_rest_nodes]
        target_host = (route_string.hostname.decode("utf-8", errors="replace")
                       if isinstance(route_string.hostname, bytes) else route_string.hostname)
        if not target_host:
            self.emit_profile_error("host_empty")
            return
        try:
            target_port = int(route_string.port)
        except (TypeError, ValueError):
            # Do not resolve arbitrary route destinations from a honeypot.
            # A non-IP hostname without a numeric service follows the 9.16
            # unknown-host path; other invalid services receive a bounded
            # error instead of unwinding the handler thread.
            try:
                ip_address(target_host)
            except ValueError:
                self.emit_profile_error("host_unknown", target_host=target_host)
            else:
                self.emit_profile_error("service_invalid",
                                        target_port=route_string.port)
            return
        route_password = (route_string.password.decode("utf-8", errors="replace")
                          if isinstance(route_string.password, bytes) else route_string.password)
        (action, talk_mode, password) = self.server.route_table.lookup_target(target_host,
                                                                              target_port)

        if action == RouteTable.ROUTE_DENY:
            self.logger.debug("Route to %s:%s denied" % (target_host, target_port))
            self.deny_route(target_host, target_port)
            return

        elif talk_mode != RouteTable.MODE_ANY and talk_mode != pkt.route_talk_mode:
            self.logger.debug("Talk mode (%d) to %s:%s denied" % (pkt.route_talk_mode,
                                                                  route_string.hostname,
                                                                  route_string.port))
            self.deny_route(target_host, target_port)
            return

        elif action == RouteTable.ROUTE_ALLOW:
            if password:
                if password == route_password:
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
                    self.deny_route(target_host, target_port)
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
        service = self.server.service_manager.find_service_by_address(target_host,
                                                                      target_port)

        # If the service wasn't found, we should return a timeout message,
        # meaning that the SAP Router tried to connect to the target service
        # but it didn't responded
        if service is None:
            self.logger.debug("Target service %s:%s not available", target_host,
                              target_port)
            self.session.add_event("Target service not available", data={"target": target_host,
                                                                         "port": target_port,
                                                                         "password": route_password},
                                   request=str(pkt))
            if pkt.route_talk_mode == RouteTable.MODE_RAW:
                # 9.16 acknowledges an allowed native/raw route first, then
                # closes the stream when the local partner is unavailable.
                self.advance_profile_count("raw_unreachable_step")
                self.request.send(SAPRouter(type=SAPRouter.SAPROUTER_PONG))
                self.close()
                return
            partner_host = ("localhost" if (self.partner_name_mode == "loopback" and
                                            target_host == "127.0.0.1")
                            else target_host)
            self.emit_profile_error("partner_unreachable", target_host=target_host,
                                    target_port=target_port,
                                    partner_host=partner_host)
            return

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
            self.advance_profile_count("route_accept_step")
            self.request.send(SAPRouter(type=SAPRouter.SAPROUTER_PONG))

    def deny_route(self, target_host, target_port):
        """Reply with a route-permission error for a denied destination."""
        self.emit_profile_error("route_denied", target_host=target_host,
                                target_port=target_port)

    def handle_control(self, pkt):
        """Handles control messages"""
        opcode_str = router_control_opcodes[pkt.opcode] if pkt.opcode in router_control_opcodes else "unknown"
        self.logger.debug("Handling control message, opcode %d (%s)",
                          pkt.opcode, opcode_str)
        # Version request
        if pkt.opcode == 1:
            self.logger.debug("Received version request (client version %d)", pkt.version)
            self.server.clients[self.client_address].ni_version = pkt.version
            self.advance_profile_count("version_request_step")
            self.request.send(SAPRouter(type=SAPRouter.SAPROUTER_CONTROL,
                                        version=self.router_version,
                                        opcode=2,
                                        return_code=-13))
        else:
            self.logger.debug("Unhandled opcode %d (%s)",
                              pkt.opcode, opcode_str)
            return self.emit_profile_error("control_unknown", opcode=pkt.opcode)

    def handle_admin(self, pkt):
        """Handles admin messages"""
        command_name = router_adm_commands.get(pkt.adm_command, "unknown")
        self.logger.debug("Handling admin message, command %d (%s)",
                          pkt.adm_command, command_name)

        if not self.external_admin:
            self.logger.debug("External administration disabled")
            if pkt.adm_command == 2:
                return self.emit_profile_error("admin_info_denied")
            return self.emit_profile_error("admin_denied")

        # Information request
        if pkt.adm_command == 2:
            self.logger.debug("Received information request (password %s)", pkt.adm_password)

            # If a password was specified but doesn't match, return error
            if self.info_password and self.info_password != pkt.adm_password.strip(b"\x00").decode():
                self.session.add_event("Information request invalid password", data=pkt.adm_password, request=str(self.packet))
                return self.emit_profile_error("admin_password_denied")
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
                          pkt.adm_command, command_name)

    def handle_timeout(self):
        """Handles timeout"""
        self.logger.debug("Timed out client")
        self.emit_profile_error("timeout")

    def error_context(self, **values):
        """Values available to profile text templates."""
        context = {"hostname": self.hostname, "release": self.release,
                   "router_version": self.router_version,
                   "router_version_patch": self.router_version_patch,
                   "peer_ip": self.client_address[0],
                   "listener_port": self.server.listener_port,
                   "timeout": self.timeout,
                   "target_host": "", "target_port": "",
                   "partner_host": "", "opcode": ""}
        context.update(values)
        return {key: str(value) for key, value in context.items()}

    def emit_profile_error(self, case, reason=None, **values):
        """Return a named version/profile-specific SAPRouter error."""
        options = render_error_options(self.error_profile, case,
                                       self.error_context(**values), reason)
        return self.return_error(**options)

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

        info_clients = b"".join([bytes(client) for client in info_clients])
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

        info_pkt = Raw(("Total no. of clients: %d\x00" % len(self.server.clients)).encode())
        self.request.send(info_pkt)
        self.session.add_event("Returned information request", data={"packet": "total_no_clients"},
                               response=str(info_pkt))

        info_pkt = Raw(("Working directory   : %s\x00" % self.route_table_working_directory).encode())
        self.request.send(info_pkt)
        self.session.add_event("Returned information request", data={"packet": "working_directory"},
                               response=str(info_pkt))

        info_pkt = Raw(("Routtab             : %s\x00" % self.route_table_filename).encode())
        self.request.send(info_pkt)
        self.session.add_event("Returned information request", data={"packet": "routtab"},
                               response=str(info_pkt))

        # Send a zero-length NI packet as end-of-data terminator
        self.request.send(Raw(b""))

        # Signal the handler loop to stop; finish() will close the socket
        # gracefully so the client receives a proper FIN instead of RST
        self.close()

    def return_error(self, **options):
        """Returns an error response"""
        profile = self.error_profile
        count_step = options.pop("count_step",
                                 profile["error_count"]["default_error_step"])
        count_after = options.pop("count_after", 0)
        if profile["error_count"]["enabled"]:
            options.setdefault("error_count", self.advance_error_count(count_step))
        self.logger.debug("Returning error code %d (%s)", options.get("return_code"),
                          router_return_codes.get(options.get("return_code"), "unknown"))

        context = self.error_context()
        fields = {key: Template(str(value)).substitute(context)
                  for key, value in profile["fields"].items()}
        fields.setdefault("error_time", datetime.now().strftime(
            str(profile["error_time_format"])))
        error_text = SAPRouterError(**fields)
        for field in list(options.keys()):
            setattr(error_text, field, str(options[field]))

        error_pkt = SAPRouter(type=SAPRouter.SAPROUTER_ERROR,
                              version=self.router_version,
                              opcode=0,
                              return_code=options.get("return_code"),
                              err_text_value=error_text)
        self.request.send(error_pkt)
        self.session.add_event("Returned error",
                               data={"return_code": options.get("return_code"),
                                     "error_msg": router_return_codes.get(options.get("return_code"), "unknown")},
                               response=str(error_pkt))
        if profile["error_count"]["enabled"] and count_after:
            self.advance_error_count(count_after)

    def advance_error_count(self, step):
        """Advance the configured process-level NI error serial."""
        current = getattr(self.server, "error_count",
                          int(self.error_profile["error_count"]["start"]))
        self.server.error_count = current + step
        return self.server.error_count

    def advance_profile_count(self, event):
        """Advance a named non-error exchange when its profile enables NI serials."""
        count = self.error_profile["error_count"]
        if count["enabled"]:
            return self.advance_error_count(int(count[event]))


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
        error_profile = resolve_error_profile(
            int(self.config.get("release", 916)),
            self.config.get("error_profile", None))
        error_count_start = int(self.config.get(
            "error_count_start", error_profile["error_count"]["start"]))
        if error_count_start < 0:
            raise ValueError("error_count_start must be nonnegative")
        super(SAPRouterService, self).setup_server()
        self.server.error_profile = error_profile
        if self.server.error_profile["error_count"]["enabled"]:
            self.server.error_count = error_count_start
        self.server.route_table = RouteTable(self.config.get("route_table", None))
        self.server.listener_port = self.listener_port
        self.server.listener_address = self.listener_address
        # Generates a random pid and records the time when the service started
        self.server.pid = self.server.config.get("pid", 0)
        self.server.time_started = self.server.config.get("time_started", datetime.today())

        # Register virtual services from the route table as synthetic clients
        # so they appear in info responses, mimicking a real SAP Router that
        # shows its backend connections in the connection table.
        self._register_virtual_clients()

    def _register_virtual_clients(self):
        """Register synthetic client entries for allowed targets in the route
        table, so they appear in the router's info response as connected
        backend services."""
        if not hasattr(self.server.route_table, 'table'):
            return
        for (host, port), (action, talk_mode, password) in self.server.route_table.table.items():
            if action != RouteTable.ROUTE_ALLOW:
                continue
            self.server.clients_count += 1
            client_key = (host, port)
            client = SAPRouterClient()
            client.id = self.server.clients_count
            client.address = self.listener_address
            client.partner = host
            client.service = str(port)
            client.routed = True
            client.connected = True
            client.connected_on = self.server.time_started
            self.server.clients[client_key] = client
