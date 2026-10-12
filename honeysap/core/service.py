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
from abc import abstractmethod, ABCMeta
# External imports
from flask.app import Flask
from gevent.event import Event
from gevent import getcurrent, spawn, joinall
from pysap.SAPNI import SAPNIServerThreaded, SAPNIServerHandler
# Custom imports
from .logger import Loggeable
from .loader import ClassLoader
from .evidence import LoggingPolicy
from .http import (HTTPConnectionHandler, HTTPResponse, HTTPServerThreaded,
                   WSGIBridge)
from .tls import server_context


WORKER_STOP_TIMEOUT = 2


class BaseService(Loggeable, metaclass=ABCMeta):
    """ Base service class
    """

    @property
    def alias(self):
        return self.config.get("alias", self.__class__.__name__)

    @property
    def listener_port(self):
        return self.config.get("listener_port", 80)

    @property
    def enabled(self):
        return self.config.get("enabled", False)

    @property
    def virtual(self):
        return self.config.get("virtual", False)

    @property
    def listener_address(self):
        return self.config.get("listener_address", "127.0.0.1")

    def __str__(self):
        return "<Service %s>" % self.alias

    def __init__(self, config, datastore, session_manager, service_manager):
        """Initialize the service with the options provided.
        """
        self.config = config
        self.datastore = datastore
        self.session_manager = session_manager
        self.service_manager = service_manager
        self.logging_policy = LoggingPolicy.from_config(config)

        # If a custom alias was defined, use that as a logger name, otherwise
        # use the default (class name)
        if self.alias != self.__class__.__name__:
            self.logger_name = self.alias

        # Setup the server to complete initialization
        self.setup_server()

        self.logger.debug("Service initialized")

    def setup_server(self):
        """Setup the server"""
        pass

    @abstractmethod
    def run(self):
        """Run the server"""
        pass

    @abstractmethod
    def stop(self):
        """Stop the server"""
        pass

    def handle_virtual(self, client, client_address, route_context=None):
        """Handles a virtual socket using a socket connected to a client."""
        pass


class BaseTCPService(BaseService):

    server_cls = SAPNIServerThreaded
    handler_cls = SAPNIServerHandler

    def setup_server(self):
        super(BaseTCPService, self).setup_server()
        self._started = False

        # Create the server and populate it with all the required objects
        # but do not bind and activate it yet
        self.server = self.server_cls((self.listener_address,
                                       self.listener_port),
                                      self.handler_cls,
                                      bind_and_activate=False)
        self.server.server = self
        self.server.allow_reuse_address = True
        self.server.config = self.config
        self.server.datastore = self.datastore
        self.server.session_manager = self.session_manager
        self.server.service_manager = self.service_manager
        self.server.logging_policy = self.logging_policy

        # Only bind and activate the server if not virtual, in that case
        # we would be passing the client's socket from other service. This
        # also avoids trying to bind to an address not valid for this host.
        if not self.virtual:
            self.server.server_bind()
            self.server.server_activate()

        self.logger.debug("Server set up on %s:%d" % (self.listener_address,
                                                      self.listener_port))

    def run(self):
        """Run the server in order to allow requests to come."""
        # Only run the server if it's not a virtual one.
        if not self.virtual:
            self.logger.debug("Waiting for clients")
            self._started = True
            try:
                self.server.serve_forever()

            except KeyboardInterrupt:
                self.logger.warning("Canceled by the user")
                raise
            finally:
                self._started = False
                self.server.server_close()

    def stop(self):
        """Stops the server."""
        self.logger.debug("Stopping server")
        if self._started:
            self.server.shutdown()
        self.server.server_close()

    def handle_virtual(self, client, client_address, route_context=None):
        """Handle virtual requests by creating a handler and passing to it the
        client socket and address."""
        # BaseRequestHandler.__init__ already calls setup(), handle(), and
        # finish(); calling handle() again reads a closed client socket.
        self.handler_cls(client, client_address, self.server)


class BaseHTTPService(BaseTCPService):
    """Base class for HTTP services.

    Connections are read by the HTTP front end (honeysap.core.http), which
    logs every request with its raw bytes and hands it to ``handle_request``.
    By default requests are answered by the service's Flask application,
    built from its ``route_*`` and ``error_*`` methods."""

    server_cls = HTTPServerThreaded
    handler_cls = HTTPConnectionHandler

    template_folder = None
    application_name = None
    # Service name recorded in the sessions and name of the request event
    session_service_name = "http"
    request_event_name = "HTTP request"
    default_max_body_bytes = 16 * 1024 * 1024

    def setup_server(self):
        # Create an Flask application for this service using the service name
        self.app = Flask(self.application_name or self.__class__.__name__,
                         template_folder=self.template_folder or None)
        self.wsgi = WSGIBridge(self.app)

        methods = dir(self)
        # Attach each route in the class
        for name in [x for x in methods if x.startswith("route_")]:
            method = getattr(self, name)
            self.app.add_url_rule(method.rule, name, method,
                                  methods=getattr(method, "methods", None))
            self.logger.debug("Adding handler '%s' for '%s' rule", name, method.rule)

        # Attach error handlers in the class
        for name in [x for x in methods if x.startswith("error_")]:
            method = getattr(self, name)
            code = int(name.split("_", 2)[1])
            self.app.register_error_handler(code, method)
            self.logger.debug("Adding handler '%s' for error code '%d'", name, code)

        tls = self.config.get("tls") or {}
        if not isinstance(tls, dict):
            raise ValueError("tls must be a mapping")
        self.tls_context = None
        if tls.get("enabled", False):
            self.tls_context = server_context(
                tls, self.config.get("hostname", "localhost"))
        self.max_body_bytes = self.config.get("max_body_bytes",
                                              self.default_max_body_bytes)

        super(BaseHTTPService, self).setup_server()

    def handle_request(self, request, connection):
        """Answer a request, returns an HTTPResponse (or None to close)."""
        return self.wsgi(request, connection)

    def request_details(self, request):
        """Service-specific fields added to the request event."""
        return {}

    def non_http_response(self, kind):
        """Response to input that is not HTTP (bytes, HTTPResponse or None
        to close the connection without answering)."""
        return None

    def bad_request_response(self, error):
        """Response to an HTTP request that could not be parsed."""
        return self.non_http_response("bad_request")

    def internal_error_response(self, request):
        return HTTPResponse(500, "Internal Server Error",
                            [("Content-Length", "0")], b"", close=True)


class ServiceManager(Loggeable):
    """ Services manager class
    """

    services_path = "honeysap/services"

    def __init__(self, config, datastore, session_manager):
        """Initialize the services manager.
        """
        self.config = config
        self.datastore = datastore
        self.session_manager = session_manager
        self.servers = []
        self.services = []
        self.stopped = Event()
        self.logger.debug("Service manager initialized")

    def add_service(self, service):
        """Add a service to the service manager."""
        self.services.append(service)
        self.logger.debug("Added service '%s' to service manager", service)

    def load_services(self):
        """Load all the services in the configuration. """

        loader = ClassLoader([BaseService],
                             self.services_path)
        try:
            configured_services = []
            for service_classname, service_cls in loader.load():
                self.logger.debug("Found service %s, looking for configuration",
                                  service_classname)

                service_configs = self.config.config_for("services", "service", service_classname)
                self.logger.info("Found %d configuration(s) for %s",
                                 len(service_configs),
                                 service_classname)

                for service_config in service_configs:
                    if service_config.get("enabled", False):
                        configured_services.append((service_classname, service_cls,
                                                    service_config))
            self._validate_configured_topology(configured_services)
            for _, service_cls, service_config in configured_services:
                service = service_cls(service_config, self.datastore,
                                      self.session_manager, self)
                self.add_service(service)
        except Exception:
            for service in self.services:
                try:
                    service.stop()
                except Exception:
                    self.logger.exception("Service cleanup failed after setup error")
            self.services = []
            self.stopped.set()
            raise

    def validate_topology(self):
        """Reject ambiguous service aliases and routed listener targets."""
        topology = [(service.alias, service.listener_address,
                     service.listener_port, service.virtual)
                    for service in self.services if service.enabled]
        self._validate_topology(topology)

    def _validate_configured_topology(self, configured_services):
        topology = []
        for service_name, _, service_config in configured_services:
            topology.append((service_config.get("alias", service_name),
                             service_config.get("listener_address", "127.0.0.1"),
                             service_config.get("listener_port", 80),
                             service_config.get("virtual", False)))
        self._validate_topology(topology)

    @staticmethod
    def _listeners_conflict(first, second):
        first_address, first_port = first
        second_address, second_port = second
        return first_port == second_port and (first_address == second_address or
                                              first_address in ("0.0.0.0", "::") or
                                              second_address in ("0.0.0.0", "::"))

    def _validate_topology(self, topology):
        aliases = set()
        routed_listeners = set()
        bound_listeners = []
        for alias, address, port, virtual in topology:
            if alias in aliases:
                raise ValueError("Duplicate service alias: %s" % alias)
            aliases.add(alias)
            listener = (address, port)
            if listener in routed_listeners:
                raise ValueError("Duplicate service listener: %s:%s" % listener)
            routed_listeners.add(listener)
            if not virtual:
                if any(self._listeners_conflict(listener, existing)
                       for existing in bound_listeners):
                    raise ValueError("Conflicting service listener: %s:%s" % listener)
                bound_listeners.append(listener)

    def find_services_by_name(self, name):
        """Returns an iterator of the registered services matching a given
        name. """
        for service in self.services:
            if service.alias == name:
                yield service

    def find_service_by_address(self, address, port):
        """Returns the registered service matching a given address and port."""
        for service in self.services:
            if service.listener_address == address and \
               service.listener_port == port:
                return service
        return None

    def run(self):
        """Starts all the registered services"""

        if self.stopped.is_set() or self.servers:
            return

        self.validate_topology()

        for service in self.services:
            if service.enabled:
                self.servers.append(spawn(service.run))
        self.logger.info("%d services launched", len(self.servers))

        try:
            if len(self.servers) > 0 and not self.stopped.is_set():
                joinall(self.servers, raise_error=True)
        except KeyboardInterrupt:
            self.logger.info('Stopping services')
            self.stop()
            raise KeyboardInterrupt
        except Exception:
            self.stop()
            raise
        finally:
            joinall(self.servers, 2)

    def stop(self):
        """Stops all started services"""
        if not self.stopped.is_set():
            first_error = None
            for service in self.services:
                try:
                    service.stop()
                except Exception as error:
                    self.logger.exception("Service failed to stop: %s", service)
                    if first_error is None:
                        first_error = error
            self.stopped.set()
            for worker in self.servers:
                if worker is getcurrent():
                    continue
                worker.join(timeout=WORKER_STOP_TIMEOUT)
                if not worker.dead:
                    worker.kill(block=True, timeout=WORKER_STOP_TIMEOUT)
                if not worker.dead and first_error is None:
                    first_error = RuntimeError("Service worker did not stop")
            if first_error is not None:
                raise first_error
