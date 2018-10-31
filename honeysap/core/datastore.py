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
from abc import abstractmethod, ABCMeta
# External imports
# Custom imports
from .logger import Loggeable
from .loader import ClassLoader


DATASTORE_DEFAULT = "MemoryDataStore"


class DataStoreNotFound(Exception):
    """Data Store class not found"""


class DataStoreKeyNotFound(Exception):
    """Key not found on the data store"""


class BaseDataStore(Loggeable):
    """Base DataStore class.
    """

    __metaclass__ = ABCMeta

    def __init__(self):
        self.notifiers = {}

    @abstractmethod
    def get_data(self, key):
        """Obtains the value stored for a given key.
        """
        pass

    @abstractmethod
    def put_data(self, key, value):
        """Puts a value on a key.
        """
        self.notify_data(key, value)

    def watch_data(self, key, callback):
        """Watches a value and triggers a callback when its modified.
        """
        if key not in self.notifiers:
            self.notifiers[key] = []
        self.notifiers[key].append(callback)
        self.logger.debug("Registered watcher for key '%s'" % key)

    def unwatch_data(self, key, callback=None):
        """Removes a watcher on a value.
        """
        # Check if there are watchers registered for the key
        if key not in self.notifiers:
            return

        # If no specific callback was provided, remove all the watchers for
        # this key
        if callback is None:
            self.notifiers[key] = []
        # Otherwise remove the specified callback
        else:
            try:
                self.notifiers[key].remove(callback)
            except ValueError:
                pass

    def notify_data(self, key, value=None):
        """Notifies that a value was modified triggering the registered
        callback.
        """
        # If the key has watcher
        if key in self.notifiers:

            self.logger.debug("Notifying watchers for key '%s'" % key)

            # If value was not provided, get it from the data store
            if value is None:
                value = self.get_data(key)

            # Callback each one of the watchers
            for callback in self.notifiers[key]:
                callback(key, value)

    def load_config(self, config):
        """Loads data from a Configuration instance into the data store.
        """
        self.logger.debug("Loading configuration data in data store")

        # Put the data of each key in the configuration
        for key in config:
            self.put_data(key, config.get(key))


class DataStoreManager(Loggeable):
    """Manager in charge of handling the Data Store
    """

    datastore = None
    datastore_path = "honeysap/datastores"

    def __init__(self, config):
        self.config = config
        self.datastore_classname = self.config.get("datastore_class",
                                                   DATASTORE_DEFAULT)

        loader = ClassLoader([BaseDataStore], self.datastore_path)
        self.datastore_cls = loader.find(self.datastore_classname)
        if self.datastore_cls is None:
            raise DataStoreNotFound("Data store class %s not found" % self.datastore_classname)

        self.logger.info("Data store manager initialized with data store %s" % self.datastore_classname)

    def get_datastore(self):
        if self.datastore is None:
            self.datastore = self.datastore_cls()
            self.datastore.load_config(self.config)
            self.logger.debug("Created data store %s" % self.datastore_classname)
        return self.datastore
