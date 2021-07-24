# HoneySAP - SAP low-interaction honeypot
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
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
#   Martin Gallo (@martingalloar) from SecureAuth's Innovation Labs team.
#

# Standard imports
from abc import abstractmethod, ABCMeta
# External imports
from flask.app import Flask
from gevent.event import Event
from gevent import spawn, wait, joinall
from pysap.SAPNI import SAPNIServerThreaded, SAPNIServerHandler
# Custom imports
from .logger import Loggeable
from .loader import ClassLoader


class BaseService(Loggeable):
    """ Base service class
    """

    __metaclass__ = ABCMeta

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

    def handle_virtual(self, client, client_address):
        """Handles a virtual socket using a socket connected to a client."""
        pass


class BaseTCPService(BaseService):

    server_cls = SAPNIServerThreaded
    handler_cls = SAPNIServerHandler

    def setup_server(self):
        super(BaseTCPService, self).setup_server()

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
            try:
                self.server.serve_forever()

            except KeyboardInterrupt:
                self.logger.warning("Canceled by the user")
                self.stop()

    def stop(self):
        """Stops the server."""
        # Only stop the server if it's not a virtual one.
        if not self.virtual:
            self.logger.debug("Stopping server")
            self.server.shutdown()

    def handle_virtual(self, client, client_address):
        """Handle virtual requests by creating a handler and passing to it the
        client socket and address."""
        handler = self.handler_cls(client, client_address, self.server)
        handler.handle()


class BaseHTTPService(BaseService):

    template_folder = None
    application_name = None

    def setup_server(self):
        super(BaseHTTPService, self).setup_server()

        # Create an Flask application for this service using the service name
        self.app = Flask(self.application_name or self.__class__.__name__,
                         template_folder=self.template_folder or None)

        methods = dir(self)
        # Attach each route in the class
        for name in [x for x in methods if x.startswith("route_")]:
            method = getattr(self, name)
            self.app.add_url_rule(method.rule, name, method)
            self.logger.debug("Adding handler '%s' for '%s' rule", name, method.rule)

        # Attach error handlers in the class
        for name in [x for x in methods if x.startswith("error_")]:
            method = getattr(self, name)
            code = int(name.split("_", 2)[1])
            self.app.error_handler_spec[None][code] = method
            self.logger.debug("Adding handler '%s' for error code '%d'", name, code)

    def run(self):
        self.logger.debug("Waiting for clients")
        try:
            self.app.run(self.listener_address,
                         self.listener_port)
        except KeyboardInterrupt:
            self.logger.warning("Canceled by the user")
            self.stop()

    def stop(self):
        self.logger.debug("Stopping server")


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
        for service_classname, service_cls in loader.load():
            self.logger.debug("Found service %s, looking for configuration",
                              service_classname)

            service_configs = self.config.config_for("services", "service", service_classname)
            self.logger.info("Found %d configuration(s) for %s",
                             len(service_configs),
                             service_classname)

            for service_config in service_configs:
                if service_config.get("enabled", False):
                    service = service_cls(service_config,
                                          self.datastore,
                                          self.session_manager,
                                          self)
                    self.add_service(service)

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

        for service in self.services:
            if service.enabled:
                self.servers.append(spawn(service.run))
        self.logger.info("%d services launched", len(self.servers))

        try:
            if len(self.servers) > 0 and not self.stopped.is_set():
                wait()
        except KeyboardInterrupt:
            self.logger.info('Stopping services')
            self.stop()
            raise KeyboardInterrupt
        finally:
            joinall(self.servers, 2)

    def stop(self):
        """Stops all started services"""
        if not self.stopped.is_set():
            for service in self.services:
                service.stop()
            self.stopped.set()
