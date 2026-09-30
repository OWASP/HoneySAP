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

Release reported in error replies. An omitted release uses the neutral value
``0``. A release value may be an integer or a numeric string. The value is
identity metadata only and does not select error behavior; import or inline
an ``error_profile`` to emulate a particular build.

``error_profile``:

Partial, service-local overrides for SAPRouter error replies. Unlisted values
use a release-neutral baseline intended to keep the service bounded, not to
emulate a particular build. The profile supports:

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
  also accepts ``line_by_reason`` with ``no_hops``, ``no_hops_one_entry``,
  ``missing_route_bytes``, ``bad_length``, ``bad_entries``, ``zero_offset``,
  ``bad_offset``, and ``bad_rest`` keys.
* ``error_count``: ``enabled``, ``start``, ``default_error_step``,
  ``version_request_step``, ``route_accept_step``, and
  ``raw_unreachable_step`` for the process-level NI serial. Error cases can
  set their own ``count_step`` and ``count_after``.
* ``max_request_length``: maximum NI payload size accepted by the handler.
  The neutral baseline is ``null`` (no profile-level limit). Set a positive
  integer to enforce a limit or ``null`` to disable it.
* ``oversized_request_error``: whether an over-limit request receives the
  configurable ``packet_too_big`` error. The default is ``false``, which
  closes the connection without an error frame. A profile can enable it when
  the emulated build returns a structured error instead.
* ``unknown_packet_error``: whether an unrecognized, in-limit packet gets
  the configurable ``route_expected`` error. The neutral baseline is
  ``false``.
* ``error_time_format``: ``strftime`` format for the dynamic error timestamp.
* ``partner_name_mode``: ``literal`` or ``loopback`` for a permitted but
  unreachable loopback partner.

Text values use ``$name`` or ``${name}`` placeholders. Available names are
``hostname``, ``release``, ``router_version``, ``router_version_patch``,
``peer_ip``, ``target_host``, ``target_port``, ``partner_host``,
``listener_port``, ``opcode``, ``timeout``, and ``route_ni_version``. Use ``$$`` for a literal dollar
sign. The ``packet_too_big`` case also receives ``request_length`` and
``max_request_length``. Unknown case names, fields, and placeholders reject
the configuration before the SAPRouter listener is started.

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

Constructing error profiles
---------------------------

Files matching ``profiles/saprouter-*.yml`` are standalone examples of the
same configuration mechanism; they are not a fixed list of supported
versions. Profiles may be added, replaced, or removed as reference behavior
is collected and maintained.

To construct a profile, start with an ordinary ``SAPRouterService`` entry,
set the identity fields such as ``release``, ``router_version``, and
``router_version_patch``, then place observed differences under
``error_profile``. Prefer partial overrides of the built-in baseline unless a
self-contained profile is needed for distribution. Keep dynamic values as
templates, and expose behavioral differences such as request limits or error
serial steps as settings instead of branching on a particular release in the
handler.

The error mapping can be kept in a separate YAML fragment and imported from
the service definition. Include paths are relative to the file containing the
``!include`` directive:

.. code-block:: yaml

   services:
     - service: SAPRouterService
       enabled: true
       release: 800
       error_profile: !include error_profiles/example.yml

The imported file contains the mapping that would otherwise be written below
``error_profile``; it must not repeat the ``error_profile`` key:

.. code-block:: yaml

   fields:
     release: "$release"
     module: "nirout.cpp"
   errors:
     route_denied:
       return_code: -94
       error: "route permission denied"

Every shipped ``saprouter-*.yml`` file is discovered by the SAPRouter tests.
The tests parse it, require exactly one enabled ``SAPRouterService``, and
resolve its complete error profile. Behavioral tests exercise the profile
mechanism independently with synthetic inline overrides, so changing the set
of packaged versions does not require adding or deleting version-named test
cases. A new setting still requires focused positive, negative, validation,
and handler coverage.

These templates emulate observable behavior; they are not evidence that every
build shares the same internal module paths or error serial behavior.

Request-length and unknown-packet behavior come from the selected profile.
Malformed route length is checked before hop
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

Target port accepts a port range. Target address accepts an individual IPv4
address, a CIDR network, or SAProuter-style IPv4 wildcards such as
``127.0.0.*``. Matching is evaluated against the ordered rules; a large
network or port range does not create connected clients or require every
address/port pair to be materialized.

The first matching entry takes precedence. A permitted target still needs a
reachable listener: for a virtual target, a ``ForwarderService`` can supply a
raw TCP backend without exposing its own listener.

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
