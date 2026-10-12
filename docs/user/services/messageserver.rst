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
Frames too short to decode as SAPMS are logged as ``Unparsed input`` with
``stage: decode`` and the raw bytes (see :ref:`Evidence logging
<evidence-logging>`).


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
balancing and web dispatcher clients may contact this port. Server-list and
group-information endpoints are not implemented.


Capabilities
~~~~~~~~~~~~

**HTTP request logging**

Every request produces an ``MS HTTP request`` event with the same fields as
the ICM (raw request and response bytes, all headers, body; see
:ref:`HTTP services evidence <http-evidence>`) plus ``action``:

- ``msgserver`` for paths beginning with ``/msgserver``; they receive
  HTTP 404.
- ``redirect_to_icm`` for all other paths, which are redirected to the ICM
  service (HTTP 301).

**Redirect to ICM**

Non-``/msgserver`` requests receive a ``301 Moved Permanently`` response
pointing at ``http://<hostname>:<icm_port><original_path>``.  The ICM port
is read from the co-configured ICM service; it defaults to 8000.

**Realistic server identity**

Redirect responses include a ``Server`` header of the form::

    SAP Message Server, release <release> (<instance>)

**Non-HTTP input**

Like the Message Server, input that is not an HTTP request (including TLS) is
not answered; the connection is closed and the input is logged as
``Non-HTTP input``.


Configuration options
~~~~~~~~~~~~~~~~~~~~~

``release``:

Integer SAP release number used in the redirect ``Server`` response header
(e.g. ``720``).

``instance``:

SAP instance name returned in the ``Server`` header (e.g. ``"PRD"``).

``hostname``:

Hostname used when constructing the ICM redirect URL.

``redirect_hostname``:

Optional redirect authority override. Set this to ``request`` to reuse the
HTTP ``Host`` authority supplied by the client (with the ICM port substituted).
This is useful for Docker deployments where the emulated hostname is not
resolvable by the client.


Example configuration
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: yaml

   service: SAPMSHTTPService
   alias: MessageServerHTTPService
   enabled: yes
   listener_port: 8100

   release: 720
   instance: PRD
   hostname: sapnw702
   redirect_hostname: request
