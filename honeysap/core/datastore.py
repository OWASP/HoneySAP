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
from abc import abstractmethod, ABCMeta
# External imports
from gevent import getcurrent, spawn
from gevent.queue import Full, Queue
# Custom imports
from .logger import Loggeable
from .loader import ClassLoader


DATASTORE_DEFAULT = "MemoryDataStore"
_VALUE_UNSET = object()
WATCHER_QUEUE_MAXSIZE = 1000


class DataStoreNotFound(Exception):
    """Data Store class not found"""


class DataStoreKeyNotFound(Exception):
    """Key not found on the data store"""


class BaseDataStore(Loggeable, metaclass=ABCMeta):
    """Base DataStore class.
    """

    def __init__(self):
        self.notifiers = {}
        self._watch_queues = {}
        self._watch_workers = {}
        self.dropped_notifications = 0

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
        if callback not in self.notifiers[key]:
            self.notifiers[key].append(callback)
            self._start_watcher(callback)
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
        self._stop_unused_watchers()

    def _start_watcher(self, callback):
        if callback in self._watch_workers:
            return
        queue = Queue(maxsize=WATCHER_QUEUE_MAXSIZE)
        self._watch_queues[callback] = queue
        self._watch_workers[callback] = spawn(self._dispatch_watcher, callback, queue)

    def _dispatch_watcher(self, callback, queue):
        while True:
            key, value = queue.get()
            try:
                callback(key, value)
            except Exception:
                self.logger.exception("Watcher failed for key '%s'", key)
            if not self._callback_active(callback):
                self._watch_workers.pop(callback, None)
                self._watch_queues.pop(callback, None)
                return

    def _callback_active(self, callback):
        return any(callback in callbacks for callbacks in self.notifiers.values())

    def _stop_unused_watchers(self):
        for callback, worker in tuple(self._watch_workers.items()):
            if not self._callback_active(callback):
                if worker is getcurrent():
                    continue
                worker.kill(block=True)
                del self._watch_workers[callback]
                del self._watch_queues[callback]

    def stop(self):
        """Stop bounded asynchronous watcher dispatch."""
        for worker in self._watch_workers.values():
            worker.kill(block=True)
        self._watch_workers = {}
        self._watch_queues = {}

    def notify_data(self, key, value=_VALUE_UNSET):
        """Notifies that a value was modified triggering the registered
        callback.
        """
        # If the key has watcher
        if key in self.notifiers:

            self.logger.debug("Notifying watchers for key '%s'" % key)

            # If value was not provided, get it from the data store
            if value is _VALUE_UNSET:
                value = self.get_data(key)

            # Dispatch each callback independently so a slow watcher cannot
            # delay updates or another watcher's ordered delivery.
            for callback in tuple(self.notifiers[key]):
                try:
                    self._watch_queues[callback].put_nowait((key, value))
                except Full:
                    self.dropped_notifications += 1
                    self.logger.warning("Watcher queue full for key '%s'", key)

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
            datastore = self.datastore_cls()
            data = self.config.get("datastore", {})
            if not isinstance(data, dict):
                raise ValueError("datastore must be a mapping")
            datastore.load_config(data)
            self.datastore = datastore
            self.logger.debug("Created data store %s" % self.datastore_classname)
        return self.datastore

    def stop(self):
        if self.datastore is not None:
            self.datastore.stop()
