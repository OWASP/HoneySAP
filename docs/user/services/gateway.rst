.. SAP Gateway service

SAP Gateway service
===================

Implementation of the SAP RFC Gateway service (``sapgw<NN>`` / port 3300+).
The gateway emulates the ABAP RFC engine: it handles CPIC/APPC connections,
responds to infrastructure calls (``RFC_SYSTEM_INFO``,
``RFC_GET_FUNCTION_INTERFACE``, ``DDIF_FIELDINFO_GET``), and records every
credential and business function call that arrives.


Connection flow
---------------

The NWRFC SDK establishes an RFC connection in several steps, each of which
the gateway handles and records:

1. ``F_INITIALIZE_CONVERSATION`` — APPC setup; carries OS username, destination
   LU, and TP name.
2. ``F_SET_PARTNER_LU_NAME`` — partner LU negotiation.
3. ``F_ALLOCATE`` — conversation allocation.
4. ``F_SAP_SEND`` (login) — first business packet; carries SAP logon username,
   client number, XOR-scrambled password, client IP, and hostname.
5. ``F_SAP_SEND`` (RFC calls) — one packet per function module invocation.


Capabilities
------------

**Credential capture**

Every ``F_INITIALIZE_CONVERSATION`` and ``F_SAP_SEND`` (login) packet is
parsed for:

- SAP logon username (``cpic_username1``, marker ``0x0111`` — variable-length
  TLV, no size constraint, always reliable)
- OS / client-side username (``SAPRFCDTStruct.user`` in
  ``F_INITIALIZE_CONVERSATION`` — 12-byte CPI-C null-terminated field; see
  :ref:`limitations <gateway-limitations>`)
- SAP client number (mandant)
- XOR-scrambled password — stored as hex and decoded to plaintext using the
  known NWRFC SDK key
- Client IP address and hostname

**Infrastructure call handling**

The following SDK-internal calls are answered automatically and logged at
INFO level:

- ``RFC_PING`` — acknowledged with an empty success response; used by clients
  as a connectivity check.
- ``RFC_SYSTEM_INFO`` — returns a populated ``RFCSI`` structure with the
  configured hostname, SID, instance number, release, and Unicode/code-page
  indicators.
- ``RFC_GET_FUNCTION_INTERFACE`` — returns the full parameter interface for
  any function module present in the RFM catalog (see below), or a minimal
  synthetic layout for unknown modules.
- ``DDIF_FIELDINFO_GET`` — returns the field layout for any structure or
  table type present in the DDIC catalog (see below), or a synthetic
  single-field CHAR structure for unknown types.

**Business function call logging**

All function calls not listed above are treated as business calls and
highlighted at WARNING level.  For each call the gateway records the function
module name, the authenticated session identity, and — where the NWRFC SDK
wire-encodes parameters as ASCII XML — the full parameter tree including
nested ABAP internal table rows, decoded inline.

**RFM catalog-driven responses**

When a ``rfm_catalog`` CSV is configured, the gateway serves accurate
``RFC_GET_FUNCTION_INTERFACE`` responses for every function module present
in the catalog.  Calls for unknown function modules fall back to a synthetic
single-string parameter response so the NWRFC SDK can still complete the call.

**DDIC catalog-driven structure layout**

When a ``ddic_catalog`` CSV is configured, ``DDIF_FIELDINFO_GET`` responses
include the exact field layout (name, type, length, offset) exported from a
real SAP system.  The gateway handles the NWRFC SDK's two-call sequence and
synthesises correct NUC/UC size values, LINES_DESCR XML for nested internal
tables (TTYP), and suppressed sub-type registrations.

**CVE-2025-42957 detection**

Calls to ``/SLOAE/DEPLOY`` are recognised as exploitation attempts for
CVE-2025-42957 (arbitrary ABAP code injection via the Software Lifecycle
Analysis Engine).  The injected ABAP code is extracted from the ``IT_MODULE``
table parameter and logged line-by-line at WARNING level.  A dedicated session
event ``SLOAE deploy payload`` is emitted containing the target report name,
module GUID, and full ABAP source.


Session events
--------------

The following named events are emitted to configured feeds (log file,
HPFeed, etc.) and can be used for SIEM alerting:

``Normal client connection``
    Emitted on initial TCP connect; records ``req_type``, LU, TP, service
    name, and client address.

``APPC init conversation``
    Emitted on ``F_INITIALIZE_CONVERSATION``; records ``func_type``,
    ``user`` (OS username), ``long_lu``, ``long_tp``, ``short_dest_name``,
    ``conversation_id``.  ``os_user_truncated: true`` is added when the
    OS username field appears to have been truncated by the SDK.

``RFC login``
    Emitted on the first ``F_SAP_SEND`` (login handshake); records
    ``username`` (SAP logon user), ``client_number``, ``password``,
    ``password_hash``, ``client_ip``, ``client_hostname``, ``program``.

``RFC function call``
    Emitted for every subsequent ``F_SAP_SEND`` business call; records
    ``function_module`` and, when present, ``xml_data`` containing the
    decoded parameter tree.

``SLOAE deploy payload``
    Emitted specifically for ``/SLOAE/DEPLOY`` calls (CVE-2025-42957);
    records ``report_name``, ``module_guid``, and ``abap_lines``.


Configuration options
---------------------

``hostname``:

SAP application server hostname returned in system-info responses.

``sid``:

SAP System ID (e.g. ``PRD``).

``instance_number``:

Two-digit SAP instance number (e.g. ``"00"``). Used to construct the
system number in system-info responses.

``rfm_catalog``:

Path to the semicolon-delimited RFC function module catalog CSV exported
from SAP using the ``Z_HONEYSAP_EXPORT`` ABAP report (found in ``tools/``).
Required columns: ``FUNCNAME``, ``REMOTE_CALL``, ``UPDATE_TASK``,
``EXCEPTION_CLASSES``, ``SHORT_TEXT``, plus per-parameter columns
``PARAMCLASS``, ``PARAMETER``, ``TABNAME``, ``FIELDNAME``, ``EXID``,
``POSITION``, ``OFFSET``, ``INTLENGTH``, ``DECIMALS``, ``DEFAULT``,
``PARAMTEXT``, ``OPTIONAL``.

When not set, ``RFC_GET_FUNCTION_INTERFACE`` responses use a minimal
synthetic parameter layout.

``ddic_catalog``:

Path to the semicolon-delimited DDIC structure field definition CSV
exported alongside the RFM catalog by ``Z_HONEYSAP_EXPORT``.
Required columns: ``TABNAME``, ``FIELDNAME``, ``POSITION``, ``KEYFLAG``,
``DATATYPE``, ``LENG``, ``OUTPUTLEN``, ``DECIMALS``, ``INTTYPE``,
``INTLEN``, ``OFFSET``, ``OFFSET_UNI``, ``ROLLNAME``, ``REPTEXT``.

When not set, ``DDIF_FIELDINFO_GET`` responses use synthetic single-field
CHAR structures.


Catalog export
--------------

Use the ``Z_HONEYSAP_EXPORT`` ABAP report in ``tools/`` to export both
catalogs from a reference SAP system in one step.  The report writes two
files — ``honeysap_rfm.csv`` and ``honeysap_ddic.csv`` — which can be
placed in the ``data/`` directory and referenced by the profile.

Alternatively, ``tools/ztfdir_rfcint_to_spool_csv.abap`` exports the
``TFDIR`` / ``FUPARAREF`` function module catalog to a spool file for
manual extraction.


.. _gateway-limitations:

Known limitations
-----------------

**OS username truncation**

The CPI-C ``SAPRFCDTStruct.user`` field transmitted in
``F_INITIALIZE_CONVERSATION`` is a null-terminated C string in a 12-byte
buffer.  The NWRFC SDK uses ``strlcpy``-style semantics: for OS usernames
of exactly 12 characters the null terminator overwrites the last character,
so only 11 characters are received.  When this is detected the event data
includes ``os_user_truncated: true`` and the INFO log line marks the value
with a ``?`` suffix.

The SAP logon username captured from ``F_SAP_SEND`` (``cpic_username1``,
marker ``0x0111``) is not subject to this limitation and should be used as
the authoritative client identity.

**cpic_username2 availability**

The ``cpic_username2`` TLV (marker ``0x0009``) — a second OS username field
present in some SAP GUI connections — is not transmitted by all NWRFC SDK
versions.  When absent, ``os_username`` is not populated in the RFC login
event.


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

   # Optional: path to catalog CSVs exported with Z_HONEYSAP_EXPORT
   rfm_catalog: data/honeysap_rfm.csv
   ddic_catalog: data/honeysap_ddic.csv
