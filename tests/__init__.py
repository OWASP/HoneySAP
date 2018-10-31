# ===========
# HoneySAP - SAP low-interaction honeypot
#
# Copyright (C) 2015 by Martin Gallo, SecureAuth Corporation
#
# The library was designed and developed by Martin Gallo from
# SecureAuth Corporation's Labs team.
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
# ==============

# Standard imports
import unittest
# Custom imports
from tests import base_test
from tests import config_test
from tests import datastore_test
from tests import event_test
from tests import feed_test
from tests import service_test
from tests import session_test

from tests import feeds
from tests import services


def suite():
    suite = unittest.TestSuite()
    suite.addTests(base_test.suite())
    suite.addTests(config_test.suite())
    suite.addTests(datastore_test.suite())
    suite.addTests(event_test.suite())
    suite.addTests(feed_test.suite())
    suite.addTests(session_test.suite())
    suite.addTests(service_test.suite())

    suite.addTests(feeds.suite())
    suite.addTests(services.suite())
    return suite


if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())
