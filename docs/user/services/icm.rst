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

**Realistic server identity**

Responses include a ``Server`` header of the form::

    SAP NetWeaver Application Server <release> / ICM <release>

where ``<release>`` is the configured SAP release version.

**SAP-branded error pages**

All requests return SAP-styled HTML error pages (404 for unknown paths,
400 for bad requests), indistinguishable from a real lightly-configured
SAP NetWeaver system.


Configuration options
---------------------

``release``:

SAP release version string used in the ``Server`` response header
(e.g. ``"720"``).  Defaults to the global ``release`` setting.

``icm_release``:

Optional separate release version for the ICM component.  When omitted,
the same value as ``release`` is used.

``hostname``:

Hostname of the simulated SAP instance.  Used in error page details
embedded in HTML responses.


Example configuration
---------------------

.. code-block:: yaml

   service: SAPICMService
   alias: ICMService
   enabled: yes
   listener_port: 8000

   release: "720"
   hostname: sapnw702
