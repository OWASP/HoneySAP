# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

import unittest

from honeysap.core.config import Configuration
from honeysap.core.persona import SystemPersona


class SystemPersonaTest(unittest.TestCase):

    def test_defaults_and_instance_name(self):
        persona = SystemPersona()
        self.assertEqual(persona.instance_name, "sapnw702_PRD_00")
        self.assertEqual(persona.db_host, "sapnw702")

    def test_unknown_option_is_rejected(self):
        with self.assertRaises(ValueError):
            SystemPersona(bogus=1)

    def test_service_options_override_system(self):
        config = Configuration({"system": {"sid": "A4H", "hostname": "vhcala4hci"},
                                "services": [{"service": "S", "sid": "QAS",
                                              "instance_number": 1}]})
        persona = SystemPersona.from_config(config.config_for("services", "service", "S")[0])
        self.assertEqual((persona.sid, persona.hostname, persona.instance_number),
                         ("QAS", "vhcala4hci", "01"))

    def test_rfcsi_matches_real_formatting(self):
        persona = SystemPersona(sid="A4H", hostname="vhcala4hci", ip_address="192.0.2.9")
        values = dict(persona.rfcsi())
        self.assertEqual(values["RFCHOST"], "vhcala4h")
        self.assertEqual(values["RFCDEST"], "vhcala4hci_A4H_00")
        self.assertEqual(values["RFCMACH"], "  390")
        self.assertEqual(values["RFCTZONE"], "     0")
        self.assertEqual(values["RFCIPADDR"], "192.0.2.9")

    def test_address_falls_back_to_local_address(self):
        persona = SystemPersona()
        self.assertEqual(persona.address("10.1.2.3"), "10.1.2.3")
        self.assertEqual(persona.address("0.0.0.0"), "127.0.0.1")

    def test_info_xml_escapes_values(self):
        xml = SystemPersona(hostname="a<b").rfc_system_info_xml()
        self.assertIn("<RFCHOST2>a&lt;b</RFCHOST2>", xml)


class CertificateNameTest(unittest.TestCase):

    def test_certificate_name(self):
        self.assertEqual(SystemPersona(sid="A4H", domain="wdf.sap.corp").certificate_name,
                         "A4H.wdf.sap.corp")
        self.assertEqual(SystemPersona(hostname="sapprd").certificate_name, "sapprd")
