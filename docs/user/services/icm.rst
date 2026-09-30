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

Every request received on the ICM port is captured before any route
handling.  The following fields are recorded per request:

- ``client_ip`` — source IP address
- ``method`` — HTTP verb (GET, POST, etc.)
- ``path`` — request path
- ``url`` — full URL
- ``user_agent`` — ``User-Agent`` header value
- ``host`` — ``Host`` header value

**SAP-branded error pages**

All requests return SAP-styled HTML error pages (404 for unknown paths,
400 for bad requests). The current implementation does not add a custom
SAP ``Server`` header to Flask responses.


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

Hostname of the simulated SAP instance. The current ICM templates do not
use this option.


Example configuration
---------------------

.. code-block:: yaml

   service: SAPICMService
   alias: ICMService
   enabled: yes
   listener_port: 8000

   release: "720"
   hostname: sapnw702
