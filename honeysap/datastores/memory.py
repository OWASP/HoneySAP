# ===========
# HoneySAP - SAP low-interaction honeypot
#
# SECUREAUTH LABS. Copyright (C) 2019 SecureAuth Corporation. All rights reserved.
#
# The library was designed and developed by Martin Gallo from
# the SecureAuth Labs team.
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

# External imports

# Custom imports
from honeysap.core.datastore import (BaseDataStore,
                                     DataStoreKeyNotFound)


class MemoryDataStore(BaseDataStore):
    """Data Store implementation using an in-memory key/value pair.
    """

    def __init__(self):
        """Initializes the internal data store structure.
        """
        super(MemoryDataStore, self).__init__()
        self._datastore = {}

    def get_data(self, key):
        """Gets the data from the internal data store.
        """
        if key not in self._datastore:
            raise DataStoreKeyNotFound
        return self._datastore[key]

    def put_data(self, key, value):
        """Puts the data on the internal data store.
        """
        self._datastore[key] = value
        super(MemoryDataStore, self).put_data(key, value)
