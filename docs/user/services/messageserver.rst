.. SAP Message Server service

SAP Message Server service
==========================

Two complementary services emulate the SAP Message Server: a binary TCP
service (native SAPMS protocol) and an HTTP service used by load-balancing
clients and web dispatchers.  Both record all inbound connections and
protocol data.


SAP Message Server TCP (``SAPMSService``)
-----------------------------------------

Native binary Message Server protocol on port 3600 (default).


Capabilities
~~~~~~~~~~~~

**SAPMS packet capture**

For every packet received, the service decodes the SAPMS layer and records
a ``MS packet received`` event containing:

- ``flag`` / ``flag_name`` — message flag value and human-readable name
- ``iflag`` / ``iflag_name`` — internal flag value and name
- ``opcode`` / ``opcode_name`` — operation code and name (when present)
- ``fromname`` — sender application server name
- ``toname`` — recipient name
- Raw packet bytes

Invalid packets (missing SAPMS layer) are logged as ``Invalid packet
received`` events and answered with an empty SAPMS response to keep the
client connected.


Configuration options
~~~~~~~~~~~~~~~~~~~~~

No service-specific options beyond the common ``enabled``, ``listener_port``,
and ``listener_address`` settings.


Example configuration
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: yaml

   service: SAPMSService
   alias: MessageServerService
   enabled: yes
   listener_port: 3600


SAP Message Server HTTP (``SAPMSHTTPService``)
-----------------------------------------------

HTTP-based Message Server endpoint on port 8100 (default).  SAP logon load
balancing and web dispatcher clients contact this port to retrieve server
lists and group information.


Capabilities
~~~~~~~~~~~~

**HTTP request logging**

All inbound HTTP requests are parsed and a session event is recorded:

- Requests to paths beginning with ``/msgserver`` are recorded as
  ``MS HTTP request to msgserver`` with ``method``, ``path``,
  ``user_agent``, and ``host``.
- All other paths are redirected to the ICM service (HTTP 301) and
  recorded as ``MS HTTP request redirected to ICM``.

**Redirect to ICM**

Non-``/msgserver`` requests receive a ``301 Moved Permanently`` response
pointing at ``http://<hostname>:<icm_port><original_path>``.  The ICM port
is read from the co-configured ICM service; it defaults to 8000.

**Realistic server identity**

Responses include a ``Server`` header of the form::

    SAP Message Server, release <release> (<instance>)

**Robust HTTP parsing**

The handler accepts HTTP/1.0, HTTP/1.1, and higher version strings to
handle scanner and fuzzer traffic without crashing.


Configuration options
~~~~~~~~~~~~~~~~~~~~~

``release``:

SAP release version string used in the ``Server`` response header
(e.g. ``"720"``).

``instance``:

SAP instance name returned in the ``Server`` header (e.g. ``"PRD"``).

``hostname``:

Hostname used when constructing the ICM redirect URL.


Example configuration
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: yaml

   service: SAPMSHTTPService
   alias: MessageServerHTTPService
   enabled: yes
   listener_port: 8100

   release: "720"
   instance: PRD
   hostname: sapnw702
