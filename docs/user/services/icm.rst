.. SAP ICM service

SAP ICM service
===============

Implementation of the SAP Internet Communication Manager (ICM) HTTP service.
It presents a minimal HTTP endpoint that mimics the SAP NetWeaver web tier,
records every inbound HTTP request, and returns realistic SAP-branded error
pages.


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

**SAP-branded error pages**

Unknown paths return SAP-styled HTML error pages (404). The current
implementation does not add a custom SAP ``Server`` header.


Configuration options
---------------------

``release``:

SAP release value used by ``version_string()``. Defaults to ``720``; it is
not currently inserted into HTTP responses.

``icm_release``:

Optional separate release version for the ICM component.  When omitted,
the same value as ``release`` is used by ``version_string()``. It is not
currently inserted into HTTP responses.

``hostname``:

Hostname of the simulated SAP instance. Used as the common name of the
generated TLS certificate.

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
     # Common name of the generated certificate (default: hostname)
     common_name: PRD.example.corp
     # Ask clients for a certificate like the ICM (default yes)
     request_client_cert: yes

The generated certificate copies the subject layout of an SAP system
certificate (``O=SAP, OU=SAP Web AS``) and names ``SAPNetCA_G2`` as issuer,
but it is self-signed. Use ``cert_file``/``key_file`` for a certificate of
your own.


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
