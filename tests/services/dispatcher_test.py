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

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

from scapy.packet import Raw

from pysap.SAPDiag import SAPDiagItem
from pysap.SAPEPP import SAPEPP

from honeysap.services.dispatcher.dispatcher import SAPDispatcherServerHandler


class DispatcherPassportTest(unittest.TestCase):

    def test_passport_uses_epp_model_and_diag_binding(self):
        handler = SimpleNamespace(sid="PRD", hostname="sapnw702",
                                  client_no="001", context_id="AB" * 16)
        passport = SAPDispatcherServerHandler.make_passport(handler)

        self.assertIsInstance(passport, SAPEPP)
        raw = bytes(passport)
        self.assertEqual(len(raw), 0xe6)
        decoded = SAPEPP(raw)
        self.assertEqual(decoded.length, len(raw))
        self.assertEqual(decoded.version, 3)
        self.assertEqual(decoded.component.rstrip(b" \x00"), b"PRD/sapnw702_PRD_00")
        self.assertEqual(decoded.previous_component, decoded.component)
        self.assertEqual(decoded.transaction_id.rstrip(b" \x00"), b"AB" * 16)
        self.assertEqual(decoded.client, b"001")
        self.assertEqual(decoded.root_context_id, bytes.fromhex("AB" * 16))
        self.assertEqual(bytes(decoded), raw)

        item = SAPDiagItem(item_type="APPL", item_id="ST_USER",
                           item_sid="PASSPORT_DATA", item_value=passport)
        parsed_item = SAPDiagItem(bytes(item))
        self.assertIsInstance(parsed_item.item_value, SAPEPP)
        self.assertEqual(bytes(parsed_item.item_value), raw)


class DispatcherHandlerTest(unittest.TestCase):

    def test_dispatcher_client_termination_closes_connection(self):
        handler = SAPDispatcherServerHandler.__new__(SAPDispatcherServerHandler)
        handler.client_address = ("127.0.0.1", 1)
        handler.server = SimpleNamespace(clients={handler.client_address: object()})
        handler.session = Mock()
        handler.request = Mock()
        diag = SimpleNamespace(com_flag_TERM_EOC=True, com_flag_TERM_EOP=False)
        handler.packet = MagicMock()
        handler.packet.__getitem__.return_value = diag
        handler.handle_msg()
        handler.request.close.assert_called_once_with()
        self.assertNotIn(handler.client_address, handler.server.clients)

    def test_dispatcher_malformed_initialized_packet_logs_off(self):
        handler = SAPDispatcherServerHandler.__new__(SAPDispatcherServerHandler)
        handler.client_address = ("127.0.0.1", 1)
        handler.server = SimpleNamespace(clients={handler.client_address: object()})
        handler.packet = Raw(b"invalid")
        handler.session = Mock()
        handler.request = Mock()
        handler.handle_msg()
        self.assertNotIn(handler.client_address, handler.server.clients)
        self.assertEqual(handler.session.add_event.call_args_list[0].args[0],
                         "Invalid dispatcher packet")
