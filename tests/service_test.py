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
import unittest
from unittest.mock import Mock, patch
# External imports
# Custom imports
from honeysap.core.loader import ClassLoader
from honeysap.core.config import Configuration
from honeysap.core.service import BaseService, BaseTCPService, ServiceManager


class ServiceTest(unittest.TestCase):
    pass


class ServiceManagerTest(unittest.TestCase):

    def test_service_manager(self):
        manager = ServiceManager(Configuration(), None, None)
        first = Mock(alias="first", listener_address="127.0.0.1",
                     listener_port=3200)
        second = Mock(alias="second", listener_address="127.0.0.1",
                      listener_port=3201)
        manager.add_service(first)
        manager.add_service(second)
        self.assertEqual(list(manager.find_services_by_name("first")), [first])
        self.assertIs(manager.find_service_by_address("127.0.0.1", 3201), second)
        self.assertIsNone(manager.find_service_by_address("127.0.0.1", 9999))

        first.stop.side_effect = ValueError("first stop failed")
        with self.assertRaisesRegex(ValueError, "first stop failed"):
            manager.stop()
        first.stop.assert_called_once_with()
        second.stop.assert_called_once_with()
        self.assertTrue(manager.stopped.is_set())
        manager.stop()
        manager.run()
        self.assertEqual(manager.servers, [])

    def test_service_worker_failure_is_reported(self):
        manager = ServiceManager(Configuration(), None, None)
        service = Mock(enabled=True)
        service.run.side_effect = ValueError("worker failed")
        manager.add_service(service)
        try:
            with self.assertRaisesRegex(ValueError, "worker failed"):
                manager.run()
        finally:
            manager.stop()
        service.stop.assert_called_once_with()

    def test_stop_reports_a_service_worker_that_cannot_terminate(self):
        manager = ServiceManager(Configuration(), None, None)
        manager.services = [Mock()]
        worker = Mock(dead=False)
        worker.kill.return_value = None
        manager.servers = [worker]
        with patch("honeysap.core.service.WORKER_STOP_TIMEOUT", 0.01):
            with self.assertRaisesRegex(RuntimeError, "Service worker did not stop"):
                manager.stop()
        manager.services[0].stop.assert_called_once_with()
        worker.join.assert_called_once_with(timeout=0.01)
        worker.kill.assert_called_once_with(block=True, timeout=0.01)

    def test_partial_service_load_closes_created_services(self):
        created = []
        class TrackingService:
            def __init__(self, *args):
                self.stop = Mock()
                created.append(self)

        class FailingService:
            def __init__(self, *args):
                raise ValueError("setup failed")

        config = Configuration({"services": [
            {"service": "TrackingService", "enabled": True,
             "listener_port": 3200},
            {"service": "FailingService", "enabled": True,
             "listener_port": 3201}]})
        manager = ServiceManager(config, None, None)
        with patch("honeysap.core.service.ClassLoader") as loader:
            loader.return_value.load.return_value = [
                ("TrackingService", TrackingService),
                ("FailingService", FailingService)]
            with self.assertRaisesRegex(ValueError, "setup failed"):
                manager.load_services()
        created[0].stop.assert_called_once_with()
        self.assertEqual(manager.services, [])
        self.assertTrue(manager.stopped.is_set())

    def test_topology_is_preflighted_before_any_service_is_constructed(self):
        created = []

        class TrackingService:
            def __init__(self, *args):
                created.append(self)

        config = Configuration({"services": [
            {"service": "TrackingService", "enabled": True,
             "alias": "first", "listener_port": 3200},
            {"service": "TrackingService", "enabled": True,
             "alias": "second", "listener_port": 3200}]})
        manager = ServiceManager(config, None, None)
        with patch("honeysap.core.service.ClassLoader") as loader:
            loader.return_value.load.return_value = [("TrackingService", TrackingService)]
            with self.assertRaisesRegex(ValueError, "Duplicate service listener"):
                manager.load_services()
        self.assertEqual(created, [])

    def test_topology_rejects_wildcard_listener_conflicts(self):
        manager = ServiceManager(Configuration(), None, None)
        with self.assertRaisesRegex(ValueError, "Conflicting service listener"):
            manager._validate_topology([
                ("all", "0.0.0.0", 3200, False),
                ("specific", "127.0.0.1", 3200, False)])

    def test_service_topology_rejects_duplicate_aliases_and_listeners(self):
        manager = ServiceManager(Configuration(), None, None)
        first = Mock(alias="first", listener_address="127.0.0.1", listener_port=3200)
        same_alias = Mock(alias="first", listener_address="127.0.0.1", listener_port=3201)
        manager.services = [first, same_alias]
        with self.assertRaisesRegex(ValueError, "Duplicate service alias"):
            manager.validate_topology()
        same_alias.alias = "second"
        same_alias.listener_port = 3200
        with self.assertRaisesRegex(ValueError, "Duplicate service listener"):
            manager.validate_topology()

    def test_tcp_service_stop_before_run_closes_without_shutdown(self):
        server = Mock()
        with patch.object(BaseTCPService, "server_cls", return_value=server):
            service = BaseTCPService(Configuration({"listener_port": 3200}),
                                     None, None, None)
        service.stop()
        server.shutdown.assert_not_called()
        server.server_close.assert_called_once_with()

    def test_virtual_tcp_handler_is_not_run_twice(self):
        service = BaseTCPService.__new__(BaseTCPService)
        service.handler_cls = Mock()
        service.server = Mock()
        client = Mock()
        address = ("127.0.0.1", 50000)
        service.handle_virtual(client, address)
        service.handler_cls.assert_called_once_with(client, address,
                                                    service.server)
        service.handler_cls.return_value.handle.assert_not_called()

    def test_builtin_service_discovery_is_recursive_and_unique(self):
        names = [name for name, _ in ClassLoader([BaseService],
                                                  "honeysap/services").load()]
        expected = {"ForwarderService", "SAPDispatcherService",
                    "SAPGatewayService", "SAPICMService", "SAPMSHTTPService",
                    "SAPMSService", "SAPRouterService"}
        self.assertTrue(expected.issubset(set(names)))
        self.assertEqual(len(names), len(set(names)))
        self.assertNotIn("BaseTCPService", names)


def test_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(ServiceTest))
    suite.addTest(loader.loadTestsFromTestCase(ServiceManagerTest))
    return suite


test_suite.__test__ = False


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(test_suite())
