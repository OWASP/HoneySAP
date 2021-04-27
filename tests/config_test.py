# ===========
# HoneySAP - SAP low-interaction honeypot
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# The library was designed and developed by Martin Gallo from
# the SecureAuth's Innovation Labs team.
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
import json
import unittest
from os import remove
from tempfile import mkstemp
# External imports
import yaml
# Custom imports
from honeysap.core.config import (Configuration,
                                  ConfigurationParserNotFound)


class ConfigurationTest(unittest.TestCase):

    key = "SomeKey"
    new_key = "SomeNewKey"
    new_new_key = "SomeNewNewKey"

    value = "SomeValue"
    new_value = "SomeNewValue"
    new_new_value = "SomeNewNewValue"

    def test_config(self):
        """Test the configuration object"""

        config = Configuration({self.key: self.value})

        self.assertEqual(self.value, config.get(self.key))
        self.assertEqual(self.value, config.get(self.key,
                                                self.new_value))
        self.assertEqual(self.new_value, config.get("InexistentKey",
                                                    self.new_value))

    def test_config_update(self):
        """Test the configuration object update methods"""

        config = Configuration()

        # Update from empty using careful
        config.update({self.key: self.value},
                      mode="careful")
        self.assertIs(None, config.get(self.key))

        # Update using loose mode
        config.update({self.key: self.value},
                      mode="loose")
        self.assertIs(self.value, config.get(self.key))

        # Update using careful mode
        config.update({self.new_key: self.new_value},
                      mode="careful")
        self.assertIs(self.value, config.get(self.key))
        self.assertIs(None, config.get(self.new_key))

        # Updating from another Configuration object
        config.update(Configuration({self.new_new_key: self.new_new_value}))
        self.assertIs(self.new_new_value, config.get(self.new_new_key))

    def test_config_for(self):
        """Test the config_for method lookup."""

        config = Configuration({self.key: self.value,
                                self.new_key: [{self.new_key: self.new_value,
                                                self.new_new_key: self.new_new_value},
                                               {self.new_key: self.new_new_value,
                                                self.key: self.value}]})

        self.assertEqual(self.value, config.get(self.key))
        self.assertListEqual([], config.config_for(self.new_new_key, self.new_new_key, "SomeClass"))
        self.assertListEqual([], config.config_for(self.new_key, self.new_key, "SomeClass"))
        self.assertListEqual([{self.key: self.value,
                               self.new_key: self.new_value,
                               self.new_new_key: self.new_new_value}],
                             config.config_for(self.new_key, self.new_key, self.new_value))
        self.assertListEqual([{self.key: self.value,
                               self.new_key: self.new_new_value}],
                             config.config_for(self.new_key, self.new_key, self.new_new_value))

    def test_config_parsers(self):
        """Test the update from a file."""

        test_filename = mkstemp()[1]

        # Test using invalid filenames
        config = Configuration()
        with self.assertRaises(ValueError):
            config.update("invalid_filename", from_file=True)
        with self.assertRaises(ValueError):
            config.update({}, from_file=True)

        # Test using a file with random content
        config = Configuration()
        with open(test_filename, 'w') as fd:
            fd.write("junk: %lalala%")
        with self.assertRaises(ConfigurationParserNotFound):
            config.update(test_filename, from_file=True)

        # Test using valid json
        config = Configuration()
        with open(test_filename, 'w') as fd:
            json.dump({self.key: self.value}, fd)
        config.update(test_filename, from_file=True)
        self.assertEqual(self.value, config.get(self.key))

        # Test using json with comments
        config = Configuration()
        with open(test_filename, 'w') as fd:
            fd.write("""{
            # Some one-line comment
            %s: %s,
            /* Other multi-line
            comment */
            }""" % (self.key, self.value))
        config.update(test_filename, from_file=True)
        self.assertEqual(self.value, config.get(self.key))

        # Test using valid yaml
        config = Configuration()
        with open(test_filename, 'w') as fd:
            yaml.dump({self.key: self.value}, fd)
        config.update(test_filename, from_file=True)
        self.assertEqual(self.value, config.get(self.key))

        remove(test_filename)

    def test_config_yaml_include(self):
        """Test yaml custom include directive."""

        test_filename = mkstemp()[1]
        test_filename_include = mkstemp()[1]

        with open(test_filename, 'w') as fd:
            fd.write("""---
            %s: %s
            %s: !include %s""" % (self.key, self.value,
                                  self.new_key, test_filename_include))

        with open(test_filename_include, 'w') as fd:
            yaml.dump({self.new_new_key: self.new_new_value}, fd)

        config = Configuration()
        config.update(test_filename, from_file=True)

        self.assertEqual(self.value, config.get(self.key))
        self.assertEqual({self.new_new_key: self.new_new_value}, config.get(self.new_key))

        self.assertListEqual([test_filename_include, test_filename],
                             config.get_config_files())

        remove(test_filename)
        remove(test_filename_include)

    def test_config_json_include(self):
        """Test json custom include directive."""

        test_filename = mkstemp()[1]
        test_filename_include = mkstemp()[1]

        with open(test_filename, 'w') as fd:
            fd.write("""{
            "%s": "%s",
            "%s": { "!include": "%s" }
            }""" % (self.key, self.value, self.new_key,
                    test_filename_include))

        with open(test_filename_include, 'w') as fd:
            json.dump({self.new_new_key: self.new_new_value}, fd)

        config = Configuration()
        config.update(test_filename, from_file=True)

        self.assertEqual(self.value, config.get(self.key))
        self.assertEqual({self.new_new_key: self.new_new_value}, config.get(self.new_key))

        self.assertListEqual([test_filename_include, test_filename],
                             config.get_config_files())

        remove(test_filename)
        remove(test_filename_include)


def test_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(ConfigurationTest))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(test_suite())
