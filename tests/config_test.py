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
import json
import os
import unittest
from tempfile import mkstemp, TemporaryDirectory
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

    def make_temp_file(self):
        descriptor, filename = mkstemp()
        os.close(descriptor)
        self.addCleanup(lambda: os.path.exists(filename) and os.remove(filename))
        return filename

    def make_temp_dir(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return directory.name

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

        with self.assertRaises(ValueError):
            config.update({}, mode="unknown")

    def test_config_get_does_not_mutate_values(self):
        value = {"_config_files": ["nested.json"], "key": "value"}
        config = Configuration({"nested": value})
        self.assertIs(value, config.get("nested"))
        self.assertEqual(["nested.json"], value["_config_files"])

    def test_redacted_configuration_hides_only_sensitive_configuration_values(self):
        config = Configuration({"feed_secret": "secret", "password": "password",
                                "ordinary": "visible", "nested": {"token": "value"}})
        rendered = config.redacted()
        self.assertNotIn("'secret'", rendered)
        self.assertNotIn("'value'", rendered)
        self.assertIn("visible", rendered)
        self.assertIn("***REDACTED***", rendered)

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

    def test_component_configurations_exclude_sibling_secrets(self):
        config = Configuration({"shared": "value", "feeds": [
            {"feed": "FirstFeed", "enabled": True, "feed_secret": "first"},
            {"feed": "SecondFeed", "enabled": True, "feed_secret": "second"}],
            "services": [{"service": "SAPICMService", "enabled": True,
                          "listener_port": 8000, "service_password": "private"}]})
        feed = config.config_for("feeds", "feed", "FirstFeed")[0]
        self.assertEqual(feed.get("shared"), "value")
        self.assertEqual(feed.get("feed_secret"), "first")
        self.assertIsNone(feed.get("feeds"))
        self.assertIsNone(feed.get("services"))
        service = config.config_for("services", "service", "SAPICMService")[0]
        self.assertEqual(service.get("service_password"), "private")
        self.assertEqual(service.get("services"), [{"service": "SAPICMService",
                                                      "enabled": True,
                                                      "listener_port": 8000}])

    def test_parse_error_reports_the_configuration_filename(self):
        filename = self.make_temp_file()
        with open(filename, 'w') as fd:
            fd.write("invalid: [")
        with self.assertRaisesRegex(ConfigurationParserNotFound, filename):
            Configuration().update(filename, from_file=True)

    def test_includes_cannot_escape_the_configuration_root(self):
        directory = self.make_temp_dir()
        filename = os.path.join(directory, "config.yml")
        with open(filename, 'w') as fd:
            fd.write("value: !include ../outside.yml\n")
        with self.assertRaisesRegex(ConfigurationParserNotFound,
                                    "outside configuration root"):
            Configuration().update(filename, from_file=True)

    def test_config_parsers(self):
        """Test the update from a file."""

        test_filename = self.make_temp_file()

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

    def test_config_yaml_include(self):
        """Test yaml custom include directive."""

        test_filename = self.make_temp_file()
        test_filename_include = self.make_temp_file()

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

    def test_yaml_rejects_python_object_constructors(self):
        test_filename = self.make_temp_file()
        with open(test_filename, 'w') as fd:
            fd.write("value: !!python/tuple [1, 2]\n")
        with self.assertRaises(ConfigurationParserNotFound):
            Configuration().update(test_filename, from_file=True)

    def test_config_json_include(self):
        """Test json custom include directive."""

        test_filename = self.make_temp_file()
        test_filename_include = self.make_temp_file()

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


    def test_nested_relative_json_includes_and_parser_reuse(self):
        directory = self.make_temp_dir()
        nested = os.path.join(directory, "nested")
        os.mkdir(nested)
        root = os.path.join(directory, "root.json")
        child = os.path.join(nested, "child.json")
        grandchild = os.path.join(nested, "grandchild.json")
        with open(root, "w") as fd:
            json.dump({"nested": {"!include": "nested/child.json"}}, fd)
        with open(child, "w") as fd:
            json.dump({"grandchild": {"!include": "grandchild.json"}}, fd)
        with open(grandchild, "w") as fd:
            json.dump({"value": "included"}, fd)

        first = Configuration()
        first.update(root, from_file=True)
        self.assertEqual({"grandchild": {"value": "included"}}, first.get("nested"))
        self.assertEqual([child, grandchild, root], first.get_config_files())

        second = Configuration()
        second.update(grandchild, from_file=True)
        self.assertEqual([grandchild], second.get_config_files())

    def test_nested_relative_yaml_includes(self):
        directory = self.make_temp_dir()
        nested = os.path.join(directory, "nested")
        os.mkdir(nested)
        root = os.path.join(directory, "root.yaml")
        child = os.path.join(nested, "child.yaml")
        grandchild = os.path.join(nested, "grandchild.yaml")
        with open(root, "w") as fd:
            fd.write("nested: !include nested/child.yaml\n")
        with open(child, "w") as fd:
            fd.write("grandchild: !include grandchild.yaml\n")
        with open(grandchild, "w") as fd:
            fd.write("value: included\n")

        config = Configuration()
        config.update(root, from_file=True)
        self.assertEqual({"grandchild": {"value": "included"}}, config.get("nested"))
        self.assertEqual([child, grandchild, root], config.get_config_files())

    def test_cyclic_includes_fail(self):
        directory = self.make_temp_dir()
        for extension, contents in (("json", '{"nested": {"!include": "root.json"}}'),
                                    ("yaml", "nested: !include root.yaml\n")):
            root = os.path.join(directory, "root." + extension)
            with open(root, "w") as fd:
                fd.write(contents)
            with self.assertRaises((ValueError, ConfigurationParserNotFound)):
                Configuration().update(root, from_file=True)


def test_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(ConfigurationTest))
    return suite


test_suite.__test__ = False


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(test_suite())
