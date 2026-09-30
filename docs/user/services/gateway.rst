.. SAP Gateway service

SAP Gateway service
===================

Implementation of the SAP RFC Gateway service (``sapgw<NN>`` / port 3300+).
The gateway emulates the ABAP RFC engine: it handles CPIC/APPC connections,
answers the infrastructure calls the NWRFC SDK makes (``RFC_PING``,
``RFC_SYSTEM_INFO``, ``RFC_GET_FUNCTION_INTERFACE``, ``DDIF_FIELDINFO_GET``),
records every credential and business function call that arrives, and
records gateway monitor and administration commands.


Connection flow
---------------

**Direct RFC client (NWRFC SDK)**

The NWRFC SDK establishes an RFC connection in several steps, each of which
the gateway handles and records:

1. ``GW_NORMAL_CLIENT`` — gateway-level connection request; carries LU, TP,
   service name, and the client's communication codepage (``1100``
   non-Unicode or ``4103`` Unicode).  The gateway echoes the packet back
   advertising codepage ``4103``, and remembers the client codepage to encode
   ``DDIF_FIELDINFO_GET`` responses in the form the SDK expects.
2. ``F_INITIALIZE_CONVERSATION`` — APPC setup; carries OS username, destination
   LU, and TP name.  The gateway answers with a newly generated conversation ID.
3. ``F_SET_PARTNER_LU_NAME`` — partner LU negotiation (no response).
4. ``F_ALLOCATE`` — conversation allocation.
5. ``F_SAP_SEND`` (login) — first business packet, recognised by the EBCDIC
   ``RFC`` marker; carries SAP logon username, client number, scrambled
   password, client IP, hostname, destination, and program.
6. ``F_SAP_SEND`` (RFC calls) — one packet per function module invocation.
7. ``F_DEALLOCATE`` or ``F_SAP_CANCEL`` — the gateway closes the connection.

Older RFC clients that open with ``F_SAP_INIT`` / ``F_SAP_ALLOCATE`` are
accepted and recorded as well.

**Gateway-to-gateway connection (SM59 connection test)**

When a real SAP system points an RFC destination at the honeypot, its gateway
uses a different handshake:

1. ``GW_REMOTE_GATEWAY`` — announces the remote gateway's IP, service,
   codepage, and hostname; echoed back with the ``CODE_PAGE``/``NIPING``
   flags set.
2. ``F_ACCEPT_CONVERSATION`` — carries the CPIC routing parameters and, for an
   SM59 connection test, an embedded RFC login.  Credentials are extracted and
   a login-success response is sent.
3. ``F_SAP_SEND`` — follow-up RFC calls (``RFC_PING``,
   ``RFC_GET_FUNCTION_INTERFACE``, ``DDIF_FIELDINFO_GET``).
4. 80-byte ``F_SAP_SEND`` acknowledgement — triggers the NIPING
   back-connection described below.

.. warning::

   **Outbound connection.**  To complete the SM59 connection test the
   honeypot opens a TCP connection **back to the peer's IP address on port
   3300**, sends ``NI_PING`` and waits up to 5 seconds for ``NI_PONG`` before
   closing.  This mimics real SAP gateways, but means the honeypot initiates
   traffic towards the source of the connection.  Take this into account in
   egress firewall rules; if outbound traffic is blocked the back-connection
   fails silently (logged at DEBUG) and the SM59 test on the remote side times
   out.


Capabilities
------------

**Credential capture**

The login ``F_SAP_SEND`` packet (and the embedded login in an SM59
``F_ACCEPT_CONVERSATION``) is parsed for:

- SAP logon username (``cpic_username1``, marker ``0x0111`` — variable-length
  TLV, no size constraint, always reliable)
- OS / client-side username (``cpic_username2``, marker ``0x0009``; see
  :ref:`limitations <gateway-limitations>`)
- SAP client number (mandant, marker ``0x0114``)
- Scrambled password (marker ``0x0117``) — stored as hex and descrambled to
  plaintext with SAP's RFC password scrambling algorithm (ASCII first, then
  UTF-16LE); if descrambling fails the hex value is kept
- Client IP address (``0x0007``), hostname (``0x0008``), and destination
  (``0x0006``)
- Calling program / client library

``F_INITIALIZE_CONVERSATION`` contributes the OS username
(``SAPRFCDTStruct.user``, a 12-byte CPI-C field), the long LU/TP names, the
short destination name, and the NCPIC LU/TP.  It carries no password or
client number.

**Infrastructure call handling**

The following SDK-internal calls are answered automatically and logged at
INFO level:

- ``RFC_PING`` — answered with the generic success response; used by clients
  as a connectivity check.
- ``RFC_SYSTEM_INFO`` — returns a populated 245-character ``RFCSI`` structure
  built from the ``hostname``, ``sid``, ``instance_number``,
  ``kernel_version``, ``sap_release``, ``db_system``, and ``os_name``
  options.  The honeypot always presents itself as a Unicode (``4103``)
  system.
- ``RFC_GET_FUNCTION_INTERFACE`` — returns the full parameter interface for
  any function module present in the RFM catalog (see below).  For modules
  not in the catalog, the generic success response is sent without a
  parameter interface.
- ``DDIF_FIELDINFO_GET`` — returns the field layout for a structure or table
  type (see *DDIC catalog-driven structure layout* below).

**Business function call logging**

All function calls not listed above are treated as business calls and
highlighted at WARNING level.  For each call the gateway records the function
module name, the authenticated session identity, plain import parameters,
and — where the NWRFC SDK wire-encodes parameters as ASCII XML — the full
parameter tree including nested ABAP internal table rows, decoded inline.
Business calls are answered with the generic success response.

**RFM catalog-driven responses**

When a ``rfm_catalog`` CSV is configured, the gateway serves accurate
``RFC_GET_FUNCTION_INTERFACE`` responses for every function module present
in the catalog.  The catalog's parameter lengths are also used to build
fallback structure layouts for ``DDIF_FIELDINFO_GET``.

**DDIC catalog-driven structure layout**

``DDIF_FIELDINFO_GET`` resolves the requested type in this order:

1. ``RFCSI`` — served from built-in, pre-captured responses.
2. ``ddic_catalog`` — the exact field layout (name, type, length, offset)
   exported from a real SAP system.
3. A small set of built-in structure definitions.
4. Generated CHAR fields (``DATA1``, ``DATA2``, …) covering the total length,
   if the type is referenced as a parameter in the RFM catalog.
5. Otherwise, a response with zero rows.

The gateway handles the NWRFC SDK's two-call sequence and synthesises correct
NUC/UC size values, LINES_DESCR XML for nested internal tables (TTYP), and
suppressed sub-type registrations.  String references and zero-length
placeholder fields are left out of the flat field list.

**CVE-2025-42957 detection**

Calls to ``/SLOAE/DEPLOY`` are recognised as exploitation attempts for
CVE-2025-42957 (arbitrary ABAP code injection via the Software Lifecycle
Analysis Engine).  The injected ABAP code is extracted from the ``IT_MODULE``
table parameter and logged line-by-line at WARNING level.  A dedicated session
event ``SLOAE deploy payload`` is emitted containing the target report name,
module GUID, and full ABAP source.

**Gateway monitor and administration commands**

``GW_SEND_CMD`` monitor commands are recorded.  ``SUICIDE``,
``DELETE_CONN``, ``CANCEL_CONN``, ``DISCONNECT``, ``DELETE_CLIENT``, and
``DELETE_REMGW`` are flagged as dangerous and logged at WARNING level.  Only
``NOOP`` receives a response.  ``STOP_GATEWAY`` is also flagged as dangerous;
``CHECK_GATEWAY`` is answered; TP registration and unregistration requests
are recorded without a response.


Session events
--------------

The following named events are emitted to configured feeds (log file,
HPFeed, etc.) and can be used for SIEM alerting.  Every received packet
additionally produces a ``Received packet`` event.

**RFC client events**

``Normal client connection``
    Emitted on ``GW_NORMAL_CLIENT``; records ``req_type``, ``lu``, ``tp``,
    ``service``, ``address``, and ``conversation_id`` when present.

``APPC init conversation``
    Emitted on ``F_INITIALIZE_CONVERSATION``; records ``func_type``,
    ``user`` (OS username), ``long_lu``, ``long_tp``, ``short_dest_name``,
    ``ncpic_lu``, ``ncpic_tp``, and ``conversation_id`` (see
    :ref:`limitations <gateway-limitations>`).  ``os_user_truncated: true``
    is added when the OS username may have been truncated by the SDK.

``APPC set partner LU name`` / ``APPC allocate``
    Emitted on ``F_SET_PARTNER_LU_NAME`` / ``F_ALLOCATE``; record
    ``func_type``.

``RFC login``
    Emitted on the login ``F_SAP_SEND``; records ``func_type``,
    ``conversation_id``, ``username`` (SAP logon user), ``os_username``,
    ``client_number``, ``password``, ``password_hash`` (hex of the scrambled
    value, not a cryptographic hash), ``client_ip``, ``client_hostname``,
    ``destination``, and ``program``.  Fields are only present when found in
    the packet.

``RFC function call``
    Emitted for every subsequent ``F_SAP_SEND``; records ``func_type``,
    ``conversation_id``, ``function_module`` and, when present,
    ``parameters`` (plain import parameters), ``xml_data`` (decoded XML
    parameter tree), and ``target_function`` (the module asked about in
    ``RFC_GET_FUNCTION_INTERFACE``).  On gateway-to-gateway connections it is
    also emitted for pre-login packets, which carry no ``function_module``.

``SLOAE deploy payload``
    Emitted specifically for ``/SLOAE/DEPLOY`` calls (CVE-2025-42957);
    records ``report_name``, ``module_guid``, and ``abap_code`` (the injected
    ABAP source, one line per source line, joined with newlines).

``APPC deallocate`` / ``APPC cancel request`` / ``APPC ping request``
    Emitted on ``F_DEALLOCATE``, ``F_SAP_CANCEL``, and ``F_SAP_PING``;
    record ``func_type``.

``APPC old-style init/allocate``
    Emitted on ``F_SAP_INIT`` / ``F_SAP_ALLOCATE`` from older clients;
    records ``func_type``, ``user``, and ``dest``.

``APPC TP registration``
    Emitted on ``F_SAP_REGTP`` / ``F_SAP_UNREGTP``; records ``func_type``.

**Gateway-to-gateway events**

``Remote gateway connection``
    Emitted on ``GW_REMOTE_GATEWAY``; records ``req_type``, ``gateway_ip``,
    ``service``, ``codepage``, and ``hostname``.

``Gateway system info received``
    Emitted on ``F_ACCEPT_CONVERSATION``; records ``func_type`` and the CPIC
    routing parameters as key/value pairs.  For an SM59 connection test it
    also records ``login_type: sm59_rfc`` and the same credential fields as
    ``RFC login``.

``Gateway ACK received, initiating back-connection``
    Emitted when the 80-byte acknowledgement arrives; records ``func_type``,
    ``conversation_id``, ``gw_bytes48_56``, and ``gw_pktlen``.

``Gateway NIPING back-connection complete``
    Emitted after the outbound NIPING back-connection; records ``back_to``
    (peer IP) and ``response`` (hex of the reply, or ``null``).

**Gateway administration events**

``Gateway check request``
    Emitted on ``CHECK_GATEWAY``; records ``req_type``.

``Monitor command received``
    Emitted on ``GW_SEND_CMD``; records ``req_type``, ``cmd``, and ``cmd_id``.

``Dangerous monitor command attempted``
    Emitted additionally for dangerous monitor commands; records ``cmd``.

``Dangerous gateway command attempted``
    Emitted on ``STOP_GATEWAY``; records ``req_type``.

``TP registration request`` / ``TP unregistration request``
    Emitted on ``GW_REGISTER_TP`` / ``GW_UNREGISTER_TP``; record
    ``req_type``.

``Unhandled gateway request`` / ``Unhandled APPC request``
    Emitted for any other request; record ``req_type``/``req_type_id`` or
    ``func_type``/``func_type_id``.


Configuration options
---------------------

``hostname``:

SAP application server hostname returned in system-info responses.  Only the
first 8 characters are used in the ``RFCHOST`` field.  Defaults to
``sapnw702``.

``sid``:

SAP System ID (e.g. ``PRD``), returned as system and database name.
Defaults to ``PRD``.

``instance_number``:

Two-digit SAP instance number (e.g. ``"00"``).  Used in the RFC destination
name (``<hostname>_<sid>_<instance_number>``) returned by
``RFC_SYSTEM_INFO`` and in the ``41<NN>`` service identifier in APPC
response headers.  Defaults to ``"00"``.

``kernel_version``:

Kernel release; the first three characters are returned as ``RFCKERNRL``.
Defaults to ``"7200"``.

``sap_release``:

SAP release returned as ``RFCSAPRL``.  Defaults to ``"752"``.

``db_system``:

Database system returned as ``RFCDBSYS``.  Defaults to ``HDB``.

``os_name``:

Operating system returned as ``RFCOPSYS``.  Defaults to ``Linux``.

``rfm_catalog``:

Path to the semicolon-delimited RFC function module catalog CSV exported
from SAP using the ``Z_HONEYSAP_EXPORT`` ABAP report (found in ``tools/``).
The file has the header
``FUNCNAME;REMOTE_CALL;UPDATE_TASK;REMOTE_BASXML_SUPPORTED;PARAMCLASS;PARAMETER;TABNAME;FIELDNAME;EXID;POSITION;OFFSET;INTLENGTH;DECIMALS;DEFAULT;PARAMTEXT;OPTIONAL``.
The gateway uses ``FUNCNAME``, ``REMOTE_CALL``, ``UPDATE_TASK``,
``PARAMCLASS``, ``PARAMETER``, ``TABNAME``, ``FIELDNAME``, ``EXID``,
``POSITION``, ``INTLENGTH``, ``DECIMALS``, and ``PARAMTEXT``; the remaining
columns are ignored.

When not set, ``RFC_GET_FUNCTION_INTERFACE`` responses carry no parameter
interface.

``ddic_catalog``:

Path to the semicolon-delimited DDIC structure field definition CSV
exported alongside the RFM catalog by ``Z_HONEYSAP_EXPORT``.
Required columns: ``TABNAME``, ``FIELDNAME``, ``POSITION``, ``KEYFLAG``,
``DATATYPE``, ``LENG``, ``OUTPUTLEN``, ``DECIMALS``, ``INTTYPE``,
``INTLEN``, ``OFFSET``, ``OFFSET_UNI``, ``ROLLNAME``, ``REPTEXT``.

When not set, ``DDIF_FIELDINFO_GET`` falls back to built-in definitions,
generated CHAR fields, or an empty response as described above.


Catalog export
--------------

Use the ``Z_HONEYSAP_EXPORT`` ABAP report in ``tools/`` to export both
catalogs from a reference SAP system in one step.  The report writes two
files — ``honeysap_rfm.csv`` and ``honeysap_ddic.csv`` — with
``OPEN DATASET``, so they are written to the **application server file
system** (``/tmp/`` by default, configurable on the selection screen), not
to the local PC.  Download them (e.g. with transaction ``CG3Y``), place them
in the ``data/`` directory, and reference them in the profile.

Alternatively, ``tools/ztfdir_rfcint_to_spool_csv.abap`` reads ``TFDIR`` and
calls ``RFC_GET_FUNCTION_INTERFACE`` for each function module, writing the
function module catalog to the spool for manual extraction.


.. _gateway-limitations:

Known limitations
-----------------

**OS username truncation**

The CPI-C ``SAPRFCDTStruct.user`` field transmitted in
``F_INITIALIZE_CONVERSATION`` is a null-terminated C string in a 12-byte
buffer.  The NWRFC SDK uses ``strlcpy``-style semantics: for OS usernames
of exactly 12 characters the null terminator overwrites the last character,
so only 11 characters are received.  The gateway cannot tell a truncated
name from a genuine 11-character one, so every 11-character value gets
``os_user_truncated: true`` in the event data and a ``?`` suffix in the INFO
log line.

The SAP logon username captured from ``F_SAP_SEND`` (``cpic_username1``,
marker ``0x0111``) is not subject to this limitation and should be used as
the authoritative client identity.

**cpic_username2 availability**

The ``cpic_username2`` TLV (marker ``0x0009``) carries the client's OS user
and is sent by the NWRFC SDK, but is absent in some older SAP GUI and
non-NWRFC clients.  When absent, ``os_username`` is not populated in the
RFC login event.

**Late-attached event fields**

``conversation_id`` in ``APPC init conversation``, ``target_function`` in
``RFC function call``, and the ``sloae_deploy`` data in the ``RFC function
call`` event for ``/SLOAE/DEPLOY`` are added after the event has been
queued.  Whether a feed sees them depends on timing, so they may be missing.
Use the ``conversation_id`` of the following ``F_SAP_SEND`` events and the
separate ``SLOAE deploy payload`` event instead.

**Large structures**

``DDIF_FIELDINFO_GET`` responses contain at most 14 flat fields; the NWRFC
SDK fails on larger responses.  Types with more fields are answered with
generated CHAR fields of the same total length, so field names are lost.


Example configuration
---------------------

.. code-block:: yaml

   service: SAPGatewayService
   alias: GatewayService
   enabled: yes
   listener_port: 3300
   listener_address: 0.0.0.0

   hostname: sapnw702
   sid: PRD
   instance_number: "00"

   # Optional: values returned by RFC_SYSTEM_INFO
   kernel_version: "7200"
   sap_release: "752"
   db_system: HDB
   os_name: Linux

   # Optional: path to catalog CSVs exported with Z_HONEYSAP_EXPORT
   rfm_catalog: data/honeysap_rfm.csv
   ddic_catalog: data/honeysap_ddic.csv
