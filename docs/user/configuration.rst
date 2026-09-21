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

Use ``!include`` as a special key whose string value is the path to a JSON
file. The included content replaces the object containing that key:

.. code-block:: json

    {
       "Some key":"Some value",
       "Some nested key":{
          "!include":"config/other.json"
       }
    }

``YAML``:

Use ``!include`` as a tag whose path points to a YAML file. Its content
replaces the tagged value:

.. code-block:: yaml

   Some key: Some value
   Some nested key: !include config/other.yml

Relative include paths are resolved against the file containing the include,
not the current working directory. Includes can be nested; cyclic includes
are rejected. Includes must remain within the directory containing the root
configuration file.

Comments
''''''''

Configuration files can contain comments that will be omited when parsing
the configuration.

``JSON``:

You can use one-line comments by starting a line with the ``#`` character, or
multi-line comments by using JavaScript notation ``/* comment */``:

.. code-block:: text

   {
       "Some key": "Some value",
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
   
   # Data store class
   datastore_class: MemoryDataStore

   # Bounded event delivery and session lifecycle
   event_queue_maxsize: 10000
   feed_queue_maxsize: 1000
   feed_failure_threshold: 5
   feed_retry_seconds: 60
   max_sessions: 10000
   max_campaigns: 10000
   session_ttl_seconds: 3600
   campaign_window_seconds: 3600
   
   # Address to listen for all services
   listener_address: 127.0.0.1

``event_queue_maxsize`` bounds events waiting for feeds (default ``10000``).
When the queue is full, HoneySAP drops the newest event rather than blocking a
network listener; the session and feed-manager metrics expose accepted,
dropped, queued, processed, and feed-error counters. ``session_ttl_seconds``
expires inactive connection sessions (default ``3600``). Sessions opened from
the same source address within ``campaign_window_seconds`` (default ``3600``)
share a campaign identifier; set the window to ``0`` to disable campaign
grouping. Serialized events include a schema version, event ID, per-session
sequence number, UTC timestamp, session ID, and campaign ID.

.. _event-correlation:

Interpreting event correlation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every serialized event has a ``session`` and ``campaign`` field. ``session``
identifies one service connection and is the precise key for ordering its
events by ``sequence``. ``campaign`` is a broader investigation aid: sessions
from the same source address within ``campaign_window_seconds`` share it. It
can group related scanning across services, but it is not an attacker identity
because multiple actors can share an address (for example behind NAT).

Forwarder events created after a SAPRouter handoff also include
``parent_session``. Its value is the ``session`` ID of the SAPRouter connection
that accepted the route, providing an exact join from forwarded traffic back
to the route request. Directly exposed Forwarder events have an empty
``parent_session`` because there is no upstream SAPRouter connection.

For example, analysts can group a scan with ``campaign``, inspect each
connection using ``session`` and ``sequence``, and join a routed Forwarder
payload to its SAPRouter request by matching ``parent_session`` to the router
event's ``session``.

.. _event-contents:

Reading event contents
~~~~~~~~~~~~~~~~~~~~~~

Use ``service`` and ``event`` to identify the protocol observation, then read
``data`` for decoded fields specific to that event. ``request`` and
``response`` retain the captured wire evidence as base64 text; decode them
only when the event fields do not answer the investigation question. The
``schema_version`` identifies the event format, while ``event_id`` identifies
one emitted record.

Service documentation lists its named events and detection-specific fields.
Treat them as observations of an attempted action, not proof that a target
operation succeeded.
``feed_queue_maxsize`` independently bounds each feed's delivery queue
(default ``1000``), so a slow feed cannot delay another feed. Values whose
configuration key names contain password, secret, token, credential, key, or
certificate markers are redacted from startup logs; attacker-supplied event
data is not redacted by this configuration safeguard. Binary event-data values
are retained as explicit ``{"type": "bytes", "encoding": "base64",
"value": "..."}`` objects rather than being decoded as text.
``max_sessions`` and ``max_campaigns`` bound retained connection and campaign
state (both default to ``10000``); the least recently active entry is evicted
when either limit is reached. The DataStore receives only values explicitly
listed under the top-level ``datastore:`` mapping, rather than the complete
configuration.
After ``feed_failure_threshold`` consecutive delivery failures (default ``5``),
a feed is paused for ``feed_retry_seconds`` (default ``60``) before delivery is
retried. Feed and service configurations receive only their own settings and
safe shared defaults; sibling credentials are not propagated.


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


Versioned behavior profiles
---------------------------

A service may expose a nested behavior or error profile when observable
responses vary between product builds. Such profiles are ordinary service
configuration, not a permanent registry of supported versions. The example
files under ``profiles/`` can therefore change as emulation targets are added,
updated, or retired.
