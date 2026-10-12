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

HTTP port of the Message Server (81NN, 8100 by default). Responses are
modeled on an ABAP Platform Message Server, including header names, case and
order, and report the :ref:`system persona <system-persona>` and the ports of
the configured Dispatcher, Gateway and ICM services.


Capabilities
~~~~~~~~~~~~

**Message Server commands**

- ``/msgserver``, ``/msgserver/`` and ``/msgserver/commands``: command list.
- ``/msgserver/{html,xml,text}/aslist``: application servers.
- ``/msgserver/{html,xml,text}/lglist``: logon groups (``logon_groups``).
- ``/msgserver/{html,xml,text}/logon``: logon data, including
  ``?version=1.1`` to ``1.3`` of the text format used by SAP GUI and
  load-balancing clients.
- ``/msgserver/{html,text}/group?GROUP[&GROUP...]``: logon group details;
  without a query string the kernel error page is returned.

Paths are case-sensitive. Every other path is redirected to the ICM HTTP port
with ``307 TEMPORARY REDIRECT``. The ``Host`` header of the request is echoed
in the ``host`` response header, like the Message Server does.

**HTTP request logging**

Every request produces an ``MS HTTP request`` event with the same fields as
the ICM (raw request and response bytes, all headers, body; see
:ref:`HTTP services evidence <http-evidence>`) plus ``action``
(``msgserver`` or ``redirect_to_icm``).

**Non-HTTP input**

Like the Message Server, input that is not an HTTP request (including TLS) is
not answered; the connection is closed and the input is logged as
``Non-HTTP input``.


Configuration options
~~~~~~~~~~~~~~~~~~~~~

``release``:

Release in the ``server`` header; defaults to the kernel release of the
:ref:`system persona <system-persona>`.

``instance``:

Name in the ``server`` header; defaults to the SID.

``hostname``:

Overrides the hostname of the system persona.

``logon_groups``:

Logon groups listed (default ``[PUBLIC, SPACE]``).

``dispatcher_service_name``:

Service name of the dispatcher port in the application server list (default
``tick-port`` for port 3200, the name registered in ``/etc/services``,
otherwise ``sapdpNN``).

``redirect_hostname``:

Optional redirect authority override. Set this to ``request`` to reuse the
HTTP ``Host`` authority supplied by the client (with the ICM port substituted).
This is useful for Docker deployments where the emulated hostname is not
resolvable by the client.

The DIAG, RFC, HTTP and HTTPS ports in the logon data are the listener ports
of the configured Dispatcher, Gateway and ICM services (an ICM service with
``tls`` enabled is the HTTPS port).


Example configuration
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: yaml

   service: SAPMSHTTPService
   alias: MessageServerHTTPService
   enabled: yes
   listener_port: 8100
   redirect_hostname: request
