# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

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

    def test_infrastructure_calls_log_their_parameters(self):
        handler = SAPGatewayServerHandler.__new__(SAPGatewayServerHandler)
        handler.client_address = ("127.0.0.1", 1)
        handler.session = Mock()
        handler.request = Mock()
        handler.server = SimpleNamespace(clients={})
        handler._gw_connection = False
        handler._send_rfcgfi_response = Mock()
        handler._send_ddif_response = Mock()
        raw = b"\x00" * 60
        calls = [("RFC_GET_FUNCTION_INTERFACE", {"FUNCNAME": "BAPI_USER_CREATE1"}),
                 ("DDIF_FIELDINFO_GET", {"TABNAME": "BAPIPWD", "ALL_TYPES": "X"})]
        for function, params in calls:
            handler.session.reset_mock()
            with patch.object(handler, "_extract_function_module", return_value=function), \
                    patch.object(handler, "_extract_target_function", return_value=None), \
                    patch("honeysap.services.gateway.gateway.extract_rfc_params",
                          return_value=params), \
                    patch("honeysap.services.gateway.gateway.extract_xml_data", return_value={}):
                handler._handle_sap_send(raw, "F_SAP_SEND")
            data = handler.session.add_event.call_args.kwargs["data"]
            self.assertEqual(data["parameters"], params)
        # The target of RFC_GET_FUNCTION_INTERFACE is in the event and answered
        handler.session.reset_mock()
        with patch.object(handler, "_extract_function_module",
                          return_value="RFC_GET_FUNCTION_INTERFACE"), \
                patch.object(handler, "_extract_target_function", return_value=None), \
                patch("honeysap.services.gateway.gateway.extract_rfc_params",
                      return_value={"FUNCNAME": "RFC_ABAP_INSTALL_AND_RUN"}), \
                patch("honeysap.services.gateway.gateway.extract_xml_data", return_value={}):
            handler._handle_sap_send(raw, "F_SAP_SEND")
        self.assertEqual(handler.session.add_event.call_args.kwargs["data"]["target_function"],
                         "RFC_ABAP_INSTALL_AND_RUN")
        handler._send_rfcgfi_response.assert_called_with(raw, "RFC_ABAP_INSTALL_AND_RUN")

    def test_gateway_check_uses_rfc_packet(self):
        handler = SAPGatewayServerHandler.__new__(SAPGatewayServerHandler)
        handler.client_address = ("127.0.0.1", 1)
        handler.request = Mock()
        handler.session = Mock()
        handler._handle_gateway(b"\x03\x01", 3)
        self.assertIsInstance(handler.request.send.call_args.args[0], SAPRFC)
