# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from scapy.packet import Raw
from pysap.SAPRFC import SAPRFC

from honeysap.services.gateway.gateway import SAPGatewayServerHandler

class GatewayHandlerTest(unittest.TestCase):

    def test_gateway_short_payload_and_monitor_stop_do_not_raise(self):
        handler = SAPGatewayServerHandler.__new__(SAPGatewayServerHandler)
        handler.packet = SimpleNamespace(payload=Raw(b"\x06"))
        handler.session = Mock()
        handler.client_address = ("127.0.0.1", 1)
        handler.handle_data()
        handler.session.add_event.assert_called_once()
        handler._handle_gateway(b"\x03\x05", 3)
        self.assertEqual(handler.session.add_event.call_args.args[0],
                         "Dangerous gateway command attempted")

    def test_gateway_check_uses_rfc_packet(self):
        handler = SAPGatewayServerHandler.__new__(SAPGatewayServerHandler)
        handler.client_address = ("127.0.0.1", 1)
        handler.request = Mock()
        handler.session = Mock()
        handler._handle_gateway(b"\x03\x01", 3)
        self.assertIsInstance(handler.request.send.call_args.args[0], SAPRFC)
