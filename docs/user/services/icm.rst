.. SAP ICM service

SAP ICM service
===============

Implementation of the SAP Internet Communication Manager (ICM) HTTP and
HTTPS ports. Responses are modeled on an ABAP Platform ICM, including header
names, case and order, the error pages and the public ICF services, and
report the :ref:`system persona <system-persona>`.


Capabilities
------------

**HTTP request logging**

Connections are read by the HTTP front end shared by the HTTP services (see
:ref:`HTTP services evidence <http-evidence>`). Every request produces an
``ICM HTTP request`` event with the exact request and response bytes, the
method, target, path, query, HTTP version, scheme, all headers in their
original order and case, the body, multipart part descriptions (name,
filename, content type, size) and the response status.

**Non-HTTP input**

Like the ICM, the service answers input that is not an HTTP request, including
a TLS ClientHello on a plain HTTP port, with its generic ``400 Bad HTTP
Request`` page over HTTP/1.0 and closes the connection. The input is logged
as ``Non-HTTP input``; TLS ClientHellos are fingerprinted.

**HTTPS**

With ``tls: {enabled: yes}`` the service listens for TLS like the ICM HTTPS
port. Plaintext on a TLS port is closed without an answer, as the ICM does.

**ICF services**

Requests are dispatched by path to Internet Communication Framework (ICF)
services, matching like the ICM: case-insensitive, by path segment, longest
prefix first.

- ``/sap/public/ping``, ``/sap/public/info`` (``RFC_SYSTEM_INFO`` as SOAP
  XML), ``/sap/public/icman/ping`` and ``/sap/public/bc/icf/logoff`` answer
  like the real services.
- ``/sap/admin/public/*`` redirects to the ICM administration logon page.
- Services marked ``auth`` (by default SOAP, ADT, WebGUI, BSP, Web Dynpro,
  UI5, OData, REST, Enterprise Search) answer ``401`` with a Basic
  authentication challenge for ``SAP NetWeaver Application Server
  [SID/client]``. Submitted credentials are logged as ``ICM authentication
  attempt`` events (``user``, ``password``, ``client``, ``path``) and are
  always rejected. The logon error page follows ``sap-language`` and
  ``Accept-Language`` (English or German).
- Services marked ``inactive`` answer ``403``, unknown paths ``404``, with
  the ICM error page.

HEAD requests get the headers only. ``ICM HTTP request`` events include
``icf_handler`` and ``icf_service``, and ``auth_user``/``auth_password``
when an ``Authorization: Basic`` header was sent.


**SAP Fiori launchpad**

With ``fiori_launchpad`` enabled, the ICM serves an SAP Fiori launchpad of an
ABAP Platform system (launchpad 1.136, SAPUI5 1.136): the logon page, the
shell with its catalogs, App Finder, user menu, settings and search, and the
apps of the recorded system. Two sample apps (Shop, Manage Products) and two
system apps work with data down to the object pages. Their entity sets are
recorded in full, so any page, sort order, filter or object is answered like
SAP Gateway does (``$skip``, ``$top``, ``$orderby``, ``$filter``,
``$select``, ``$expand``, ``$inlinecount``, ``$count``, keys and
navigations), also inside ``$batch``. Invalid queries get the errors of
SAP Gateway (syntax errors with their positions, unknown properties, type
mismatches, unsupported functions), in JSON or XML as the request asks;
unknown services get ``403 No service found``. Most other apps open and fail
on their OData services, as on a system where these services are not
activated. The responses come from a bundle recorded on a real system and
are filled with the :ref:`system persona <system-persona>` (SID, client,
host, instance) and the logged on user, whose name the shell shows.

- Logons on the logon page and with Basic authentication are checked against
  ``credentials`` (``auth_mode: list``), accept every user
  (``accept_any``) or reject all (``reject_all``). Each attempt is logged as
  ``FLP logon attempt`` with ``user``, ``password``, ``client`` and
  ``success``. The client is not checked: logons to any client, or
  without one, are accepted (an invalid client number is replaced by the
  persona's). A successful logon gets ``MYSAPSSO2`` and
  ``SAP_SESSIONID_<SID>_<client>`` cookies and a session; like an ICM the
  ticket's cookie domain is the request host without its first label.
- OData requests get CSRF tokens like SAP Gateway: a token is issued for
  ``x-csrf-token: Fetch`` (and only sent back to such requests) and
  checked on every request that sends one;
  modifying requests without a valid token are answered ``403 CSRF token
  validation failed``.
- Modifying requests (``POST``, ``PUT``, ``MERGE``, ``DELETE``, ``$batch``
  changesets) are logged as ``FLP data modification attempt`` and refused
  with an authorization error; reading ``$batch`` parts are answered.
- The launchpad is served over HTTP and HTTPS. With ``require_https``
  enabled it requires HTTPS like a real ICM (``403 Forbidden - SSL
  required`` on HTTP).
- At most ``max_sessions`` sessions (default 10000) are kept; beyond that the
  least recently used one is dropped. Sessions expire after an hour without
  requests.
- Host header values that are not a valid host name are not used in
  responses or cookies; the persona's host name is used instead.
- Requests of logged on users carry ``flp_user`` and ``flp_client`` in the
  ``ICM HTTP request`` events, so their actions after a logon can be
  followed.
- Requests for static resources (UI5 libraries, themes, images) are not
  logged unless the ``static_assets`` :ref:`logging option
  <evidence-logging>` is enabled; one launchpad visit loads several hundred.

Configuration::

   fiori_launchpad:
     enabled: yes
     # Recorded launchpad shipped with HoneySAP
     bundle: data/icm/flp/flp_bundle.tar.xz
     # Answer HTTP requests with 403 SSL required (default: no)
     require_https: no
     # list (default), accept_any or reject_all
     auth_mode: list
     # Accepted users; without this list well-known SAP default
     # credentials are accepted (SAP*, DDIC, EARLYWATCH, TMSADM, SAPCPIC,
     # DEVELOPER, ...). first_name/last_name are shown in the shell.
     credentials:
       - {user: DEVELOPER, password: "Welcome1",
          first_name: John, last_name: Smith}
     # Name shown for users without first_name/last_name
     default_profile: {first_name: "", last_name: ""}
     # Logon sessions kept at most
     max_sessions: 10000

Enable it on the HTTP and/or HTTPS ICM service (``tls: {enabled: yes}``).
Loading the bundle takes a few seconds at startup and about
60 MB of memory; services using the same bundle share it.

Configuration options
---------------------

``release``:

SAP release value used by ``version_string()``. Defaults to ``720``; it is
not currently inserted into HTTP responses.

``icm_release``:

Optional separate release version for the ICM component.  When omitted,
the same value as ``release`` is used by ``version_string()``. It is not
currently inserted into HTTP responses.

``icf``:

ICF services by path prefix, merged over the defaults. Values: ``ping``,
``info``, ``icman_ping``, ``logoff``, ``icm_admin``, ``auth``, ``inactive``,
``not_found``::

   icf:
     /sap/bc/soap/rfc: inactive
     /zcustom/api: auth

``hostname``:

Overrides the hostname of the :ref:`system persona <system-persona>`; also
the default common name of the generated TLS certificate.

``timeout``:

Seconds an idle connection is kept open (default ``30``).

``max_body_bytes``:

Largest request body accepted (default 16 MiB); larger requests are logged as
``Unparsed input`` and answered with the 400 page.

``tls``:

HTTPS settings::

   tls:
     enabled: yes
     # Optional; without them a certificate is generated at startup
     cert_file: /path/to/cert.pem
     key_file: /path/to/key.pem
     # Common name of the generated certificate (default: <SID>.<domain>
     # of the system persona, or its hostname)
     common_name: PRD.example.corp
     # Ask clients for a certificate like the ICM (default yes)
     request_client_cert: yes
     # Behave like an ICM HTTPS port (default yes)
     mimic_icm: yes

Without ``cert_file``/``key_file`` a certificate is generated at startup.
With ``mimic_icm`` it is issued like an SAP installation certificate
(``O=SAP, OU=SAP Web AS, OU=INITIAL``) by a generated ``SAPNetCA_G2``
intermediate below a generated ``SAP Global Root CA``, and the listener
accepts TLS 1.2 only with the ICM cipher suites in the ICM preference order.
With ``mimic_icm: no`` a plain self-signed certificate and the Python TLS
defaults are used. Known differences to an ICM: no HTTP/2 (``h2``) and no
advertised client certificate CA names.


Example configuration
---------------------

.. code-block:: yaml

   service: SAPICMService
   alias: ICMService
   enabled: yes
   listener_port: 8000

   release: "720"
   hostname: sapnw702

   # HTTPS port of the same instance
   service: SAPICMService
   alias: ICMHTTPSService
   enabled: yes
   listener_port: 44300
   hostname: sapnw702
   tls:
     enabled: yes
