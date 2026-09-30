# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

import unittest
from unittest.mock import Mock

from honeysap.core.config import Configuration
from honeysap.services.icm.icm import SAPICMService

class ICMServiceTest(unittest.TestCase):

    def test_icm_version_and_index_without_tcp_listener(self):
        service = SAPICMService(Configuration({"virtual": True,
                                               "release": 720,
                                               "icm_release": "7.20"}),
                                Mock(), Mock(), Mock())
        self.assertIn("7.20", service.version_string())
        response = service.app.test_client().get("/")
        self.assertEqual(response.status_code, 404)
