.. Configuration chapter frontend

Configuration
=============

This section covers configuration of HoneySAP.


Configuration files
-------------------

HoneySAP's configuration is done using configuration files. The supported file
formats are:

* ``JSON``
* ``YAML``

The ``YAML`` format is preferred and, if not specified, HoneySAP will try to
load the configuration from the file ``honeysap.yml`` in the current working
directory.

Parsing of the configuration files accepts some non-standard features:

* `Include statement`_ 
* `Comments`_

Include statement
'''''''''''''''''

You can include another file from a configuration file.

``JSON``:

You can use ``__include__`` as a special key for specify that you want to
include a file. The file name would be taken from the value of that key and
replaces by the content of the included  ``json`` file:

.. code-block:: json

   {"Some key": "Some value",
    "Some nested key": {
      "__include__": "path_to_the_file_to_include.json"
    }
   }

``YAML``:

You can use ``!include`` as a special keyword for specify the file you want
to include. The content of the included ``yaml`` file will replace the value
of the key:

.. code-block:: yaml

   - Some key: Some value,
     Some nested key: !include path_to_the_file_to_include.yml

Comments
''''''''

Configuration files can contain comments that will be omited when parsing
the configuration.

``JSON``:

You can use one-line comments by starting a line with the ``#`` character, or
multi-line comments by using JavaScript notation ``/* comment */``:

.. code-block:: json

   {"Some key": "Some value",
    # Here comes a one-line comment
    "Some nested key": {
      /* A multi-line comment
         this way */
      "Another key": "Another value"
    }
   }

``YAML``:

The YAML notation supports comments by using the ``#`` character:

.. code-block:: yaml

   - Some key: Some value,  # Comments could be in any part of the line
     # Or at the beginning
     Some nested key:
       - Another key: Another value 


Common configuration
--------------------

The following options are related to the core configuration of HoneySAP and common to all services:

Logging
'''''''

The following configuration options are related to the console logging output:

.. code-block:: yaml

    # Console logging configuration
    # -----------------------------
    
    # Level of console logging
    verbose: 3
    
    # Log events of all namespaces
    verbose_all: true
    
    # Use colored output
    colored_console: true


Miscellaneous
'''''''''''''

Miscellaneous configuration options:

.. code-block:: yaml

   # Miscellaneous configuration
   # ---------------------------
   
   # Enable reloading after a change in one of the configuration files
   reload: false
   
   # Data store class
   datastore_class: MemoryDataStore
   
   # Trace raw requests in feeds
   trace_raw_requests: True
   
   # Address to listen for all services
   listener_address: 127.0.0.1


SAP instance configuration
''''''''''''''''''''''''''

The following are configuration options related to the SAP instance:

.. code-block:: yaml

   # SAP instance configuration
   # --------------------------
   
   # Release version
   release: "720"
   
   # Hostname
   hostname: sapnw702
        