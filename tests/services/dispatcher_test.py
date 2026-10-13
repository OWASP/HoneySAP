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

from pysap.SAPDiag import SAPDiag, SAPDiagItem
from pysap.SAPDiagItems import (SAPDiagDyntAtom, SAPDiagDyntAtomItem, SAPDiagStep,
                                SAPDiagUIEventSource)
from pysap.SAPEPP import SAPEPP

from honeysap.services.dispatcher.dispatcher import SAPDispatcherServerHandler, diag_request


def field(text, row, col, name=None, invisible=0):
    atoms = [SAPDiagDyntAtomItem(etype=114, name_text=name, row=row, col=col, block=1)] \
        if name else []
    return atoms + [SAPDiagDyntAtomItem(etype=130, field2_text=text, field2_dlen=len(text),
                                        field2_mlen=len(text), field2_maxnrchars=len(text),
                                        attr_DIAG_BSD_INVISIBLE=invisible, row=row, col=col,
                                        block=1)]


def diag(items):
    """A DIAG request as received from the wire"""
    return SAPDiag(bytes(SAPDiag(compress=0, message=items)))


def okcode_request(okcode, atoms):
    return diag([SAPDiagItem(item_value=SAPDiagStep(step=1), item_type=16, item_id=4,
                             item_sid=38),
                 SAPDiagItem(item_value=okcode.encode(), item_type=16, item_id=12, item_sid=4),
                 SAPDiagItem(item_value=SAPDiagUIEventSource(valid_functionkey_data=1,
                                                             event_type=7, control_type=10,
                                                             event_data=0),
                             item_type=16, item_id=15, item_sid=1),
                 SAPDiagItem(item_value=SAPDiagDyntAtom(items=atoms), item_type=18,
                             item_id=9, item_sid=2)])


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

    def test_diag_request_reads_okcode_events_and_fields(self):
        atoms = field("ZEXPLOIT", 1, 24, "RS38M-PROGRAMM")
        request = diag_request(okcode_request("/nse38", atoms))
        self.assertEqual((request["okcode"], request["transaction"]), ("/nse38", "SE38"))
        self.assertEqual(request["events"], [{"type": "FUNCTIONKEY", "control": "DYNPRO",
                                              "data": 0}])
        self.assertEqual(request["fields"], [{"name": "RS38M-PROGRAMM", "text": "ZEXPLOIT",
                                              "row": 1, "col": 24}])
        self.assertIn("APPL/VARINFO/OKCODE", request["items"])

    def test_requests_after_the_login_screen_are_logged(self):
        handler = SAPDispatcherServerHandler.__new__(SAPDispatcherServerHandler)
        handler.client_address = ("127.0.0.1", 1)
        handler.server = SimpleNamespace(clients={handler.client_address: object()})
        handler.session = Mock()
        handler.request = Mock()
        handler.make_error_screen = Mock(return_value=[])
        # Login screen fields are named by their position
        atoms = field("001", 0, 20) + field("DEVELOPER", 2, 20)
        atoms += field("Secret1!", 3, 20, invisible=1)
        handler.packet = okcode_request("", atoms)
        handler.handle_msg()
        name = handler.session.add_event.call_args_list[0].args[0]
        data = handler.session.add_event.call_args_list[0].kwargs["data"]
        self.assertEqual(name, "Login request sent the client")
        self.assertEqual((data["client"], data["user"], data["password"]),
                         ("001", "DEVELOPER", "Secret1!"))
        self.assertTrue(data["fields"][2]["invisible"])
        # Later requests: one event with the transaction
        handler.session.reset_mock()
        handler.packet = okcode_request("/nSU01", [])
        handler.handle_msg()
        name = handler.session.add_event.call_args_list[0].args[0]
        data = handler.session.add_event.call_args_list[0].kwargs["data"]
        self.assertEqual((name, data["transaction"]), ("Enter sent the client", "SU01"))
        self.assertEqual(handler.session.add_event.call_count, 2)
        # Exit transaction
        handler.session.reset_mock()
        handler.packet = okcode_request("/i", [])
        handler.handle_msg()
        self.assertEqual([call.args[0] for call in handler.session.add_event.call_args_list],
                         ["Windows closed by the client", "Loggoff client"])

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
