# ===========
# HoneySAP - SAP low-interaction honeypot
#
# SECUREAUTH LABS. Copyright (C) 2019 SecureAuth Corporation. All rights reserved.
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
import unittest
# External imports

# Custom imports
from honeysap.core.config import Configuration
from honeysap.datastores.memory import (MemoryDataStore)
from honeysap.core.datastore import (BaseDataStore,
                                     DataStoreManager,
                                     DataStoreNotFound,
                                     DataStoreKeyNotFound)


datasore_data = {}


class BaseDataStoreTest(unittest.TestCase):

    key = "SomeKey"
    value = "SomeValue"
    new_value = "SomeNewValue"

    class DummyDataStore(BaseDataStore):
        """Dummy Data Store backend using an external dict for storing the data.
        """
        def get_data(self, key):
            return datasore_data[key]

        def put_data(self, key, value):
            datasore_data[key] = value

    def test_datastore_load_config(self):
        """Test loading the datastore with the config data."""

        dummy = self.DummyDataStore()
        config = Configuration({self.key: self.value})
        dummy.load_config(config)

        self.assertEqual(self.value, dummy.get_data(self.key))

    def test_datastore_watch(self):
        """Test the Data Store watch method."""

        dummy = self.DummyDataStore()

        def callback1(call_key, call_value):
            self.assertEqual(self.key, call_key)
            self.assertEqual(self.value, call_value)

        def callback2(call_key, call_value):
            self.assertEqual(self.key, call_key)
            self.assertEqual(self.value, call_value)

        def callback3(call_key, call_value):
            self.assertEqual(self.key, call_key)
            self.assertEqual(self.new_value, call_value)

        dummy.watch_data(self.key, callback1)
        # Check calling of the callback on the initial put
        dummy.put_data(self.key, self.value)
        self.assertEqual(self.value, dummy.get_data(self.key))
        # Check calling of the callback on following puts
        dummy.put_data(self.key, self.value)
        self.assertEqual(self.value, dummy.get_data(self.key))
        # Check adding a new callback function
        dummy.watch_data(self.key, callback2)
        dummy.put_data(self.key, self.value)
        self.assertEqual(self.value, dummy.get_data(self.key))
        # Check changing the callback functions and putting new data
        dummy.unwatch_data(self.key, callback1)
        dummy.unwatch_data(self.key, callback2)
        dummy.watch_data(self.key, callback3)
        dummy.put_data(self.key, self.new_value)
        self.assertEqual(self.new_value, dummy.get_data(self.key))


class MemoryDataStoreTest(unittest.TestCase):

    key = "SomeKeyInMemory"
    value = "SomeValueInMemory"
    new_value = "SomeNewValueInMemory"

    def test_memorydatastore(self):
        """Test the Memory data store get/put methods
        """

        memory = MemoryDataStore()
        memory.put_data(self.key, self.value)
        self.assertEqual(self.value, memory.get_data(self.key))
        with self.assertRaises(DataStoreKeyNotFound):
            memory.get_data("InexistentKey")


class DataStoreManagerTest(unittest.TestCase):

    def test_datastoremanager_default(self):
        """Test the DataStoreManager loading the default DataStore
        """
        manager = DataStoreManager(Configuration())
        datastore = manager.get_datastore()

        #self.assertIsInstance(datastore, MemoryDataStore)

        new_datastore = manager.get_datastore()
        self.assertIs(datastore, new_datastore)

    def test_datastoremanager_invalid(self):
        """Test the DataStoreManager loading an invalid  DataStore
        """
        with self.assertRaises(DataStoreNotFound):
            DataStoreManager(Configuration({"datastore_class": "InexistentClass"}))


def test_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(BaseDataStoreTest))
    suite.addTest(loader.loadTestsFromTestCase(MemoryDataStoreTest))
    suite.addTest(loader.loadTestsFromTestCase(DataStoreManagerTest))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(test_suite())
