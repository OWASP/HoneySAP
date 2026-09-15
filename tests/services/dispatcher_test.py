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
