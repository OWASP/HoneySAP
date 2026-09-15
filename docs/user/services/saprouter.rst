.. SAP Router service frontend

SAP Router service
==================

Implementation of the SAP Router service.


Configuration options
---------------------

``router_version``:

The major version of the SAP Router (default 40).

``router_version_patch``:

The patch level version of the SAP Router.

``release``:

Release reported in error replies. An omitted release defaults to 916. An
explicit non-916 release retains the previous generic error baseline unless
``error_profile`` overrides it. A release value may be an integer or a
numeric string. Service options inherit top-level profile values, so a
top-level ``release: 720`` still selects the older baseline unless the
SAPRouter service entry explicitly sets ``release: 916``.

``error_profile``:

Partial, service-local overrides for version-specific SAPRouter error replies.
Unlisted values use the built-in 9.16 profile for release 916, or the previous
generic baseline for an explicitly older release. The profile supports:

* ``fields``: common fields in the :class:`pysap.SAPRouter.SAPRouterError`
  text packet, including ``counter``, ``component``, ``module``, ``location``,
  ``release``, and ``version``. Any modeled error-text field can be overridden.
* ``errors``: case-specific fields and return codes. Named cases are
  ``invalid_route``, ``route_denied``, ``partner_unreachable``,
  ``control_unknown``, ``admin_info_denied``, ``admin_denied``,
  ``admin_password_denied``, ``timeout``, ``route_version_old``,
  ``host_empty``, ``host_unknown``, ``service_invalid``, and
  ``route_expected``. Each accepts the modeled
  error-text fields plus ``count_step`` and ``count_after``. ``invalid_route``
  also accepts ``line_by_reason`` with ``no_hops``, ``missing_route_bytes``,
  ``bad_length``, ``bad_entries``, ``bad_offset``, and ``bad_rest`` keys.
* ``error_count``: ``enabled``, ``start``, ``default_error_step``,
  ``version_request_step``, ``route_accept_step``, and
  ``raw_unreachable_step`` for the process-level NI serial. Error cases can
  set their own ``count_step`` and ``count_after``.
* ``max_request_length``: maximum NI payload size accepted by the handler.
  The 9.16 default is 10024 bytes; the legacy default is ``null`` (no
  profile-level limit). Set a positive integer to change the limit or
  ``null`` to disable it. Over-limit requests close without an error frame.
* ``unknown_packet_error``: whether an unrecognized, in-limit packet gets
  the configurable ``route_expected`` error. The 9.16 default is ``true``;
  the legacy default is ``false``.
* ``error_time_format``: ``strftime`` format for the dynamic error timestamp.
* ``partner_name_mode``: ``literal`` or ``loopback`` for a permitted but
  unreachable loopback partner.

Text values use ``$name`` or ``${name}`` placeholders. Available names are
``hostname``, ``release``, ``router_version``, ``router_version_patch``,
``peer_ip``, ``target_host``, ``target_port``, ``partner_host``,
``listener_port``, ``opcode``, ``timeout``, and ``route_ni_version``. Use ``$$`` for a literal dollar
sign. Unknown case names, fields, and placeholders reject the configuration
before the SAPRouter listener is started.

For example, a build with a different denial message and source line can
override only those values:

.. code-block:: yaml

   error_profile:
     fields:
       location: "Router $release on '$hostname'"
     errors:
       route_denied:
         error: "route blocked for $target_host:$target_port"
         module: "/src/router/access.cpp"
         line: "412"
       invalid_route:
         line_by_reason:
           bad_offset: "908"

The standalone :download:`9.16 profile <../../../profiles/saprouter-916.yml>` shows
the service configuration and a complete copy of the built-in error defaults.
Partial overrides are sufficient for ordinary profiles. These templates emulate
observable text; they are not evidence that every build shares the same
internal module paths or error serial behavior.

Under the default 9.16 profile, NI request payloads longer than 10024 bytes
close without an error frame; shorter non-router requests produce the
configurable ``route_expected`` error. Other profiles can change both
behaviors. Malformed route length is checked before hop
counts or offsets. The empty-host, unknown-host, old-route-version, and
invalid-service branches use profile-defined errors without outbound DNS
lookup. These checks mimic observed negative responses, not full routing
or resolver behavior.

``info_password``:

The password for information requests. When the option is set, the SAP Router
will only provide response to information requests if the password in the
requests matches.

``external_admin``:

If the external administration is enabled for this SAP router instance.

``timeout``:

Time out for accepting route requests in seconds. If a connection is
established with the SAP router and a route request is not sent within this
time, the server will timeout the connection and return an error message.

``error_count_start``:

Initial NI error serial for a profile (default 1). The router
advances this serial as it handles requests and includes it in error replies.
Set it only when matching a reference router with a known initial state; the
value is process-dependent and should not be treated as a fixed packet field.
This existing top-level option takes precedence over
``error_profile.error_count.start``.

``partner_name_mode``:

How the profile renders a permitted but unavailable loopback
partner in an error: ``literal`` (default) keeps ``127.0.0.1``; ``loopback``
renders it as ``localhost``. Reference routers can vary with local name
resolution, so select the mode that matches the intended deployment. This
existing top-level option takes precedence over
``error_profile.partner_name_mode``.

``pid``:

PID of the SAP router instance. Only used in information request responses.

``parent_port``:

Port of the parent SAP router instance. Only used in information request
responses.

``parent_pid``:

PID of the parent SAP router instance. Only used in information request
responses.

``hostname``:

Name of the host running the SAP router instance.

``route_table``:

Routing table for the SAP router instance. The expected formats are:

.. code-block:: yaml

   - <action>,<talk_mode>,<target_address>,<target_port>,<password>

   - action: <action>
     mode: <talk_mode>
     target: <target_address>
     port: <target_port>
     password: <password-or-null>

With:

.. code-block:: yaml

    <action> := allow | deny
    <talk_mode> := raw | ni | any

Target port accepts a range of ports to use. Target address accepts network
ranges as per ``nmap``'s syntaxis if the ``netaddr`` library is present.

First matching entry takes precedence and only one action/mode is allowed per IP/port
pair.

``route_table_filename``:

Name of the route table file.

``route_table_working_directory``:

Working directory of the route table file.


Example configuration
---------------------

The following example configuration options sets a SAP router instance allowing
access to ports ``3200`` to ``3209`` on internal IP address ``10.0.0.1``:

.. code-block:: yaml

   service: SAPRouterService
   enabled: yes
   listener_port: 3299

   release: 916
   router_version: 40
   router_version_patch: 7
   external_admin: false
   route_table:
     - allow,any,10.0.0.1,3200-3209,
