# Changelog

## v0.2.0.dev0 - in dev

### New features

- `honeysap/services/gateway/`: Added an SAP RFC Gateway honeypot with NWRFC
  SDK handshake support, RFM and DDIC catalogs, credential and XML parameter
  capture, and detection of `/SLOAE/DEPLOY` calls. Added catalog loaders and
  the `Z_HONEYSAP_EXPORT` ABAP export tool
  ([@randomstr1ng](https://github.com/randomstr1ng),
  [#11](https://github.com/OWASP/HoneySAP/pull/11)).
- `honeysap/services/saprouter/` and `profiles/error_profiles/`: Added
  validated, reusable SAPRouter error profiles for configurable wire behavior;
  service definitions can import profiles as YAML fragments
  ([@martingalloar](https://github.com/martingalloar)).

### Enhancements and improvements

- Deployment: Deprecated the Vagrant and Ansible definitions; Docker Compose is
  the supported self-contained deployment path.
- `honeysap/core/`: Added bounded event and per-feed queues, session expiry
  and campaign correlation, versioned event metadata, safe YAML loading,
  redacted configuration logging, and bounded DataStore visibility
  ([@martingalloar](https://github.com/martingalloar)).
- Core configuration, feeds, services, and datastores: Isolated component
  configuration, bounded watcher dispatch, added feed retry backoff, improved
  parse diagnostics, and tightened service shutdown
  ([@martingalloar](https://github.com/martingalloar)).
- Core service startup: Added service-topology validation and moved gevent
  monkey-patching to the command entrypoints
  ([@martingalloar](https://github.com/martingalloar)).
- `honeysap/services/dispatcher/`: Build Dispatcher passports with pysap's
  EPP implementation instead of manually constructing the structure
  ([@martingalloar](https://github.com/martingalloar)).
- `honeysap/services/saprouter/`: Improved control replies, route validation,
  request limits, deny and permitted-target behavior, virtual-service handoff,
  dynamic error counters, and clean routed-client shutdown. Added configurable
  malformed-request behavior and ordered CIDR and SAProuter-style wildcard
  route rules ([@martingalloar](https://github.com/martingalloar)).
- `honeysap/core/config.py`: Added relative and nested JSON/YAML includes,
  include-cycle detection, and non-mutating option lookup
  ([@martingalloar](https://github.com/martingalloar)).
- Core feeds, sessions, events, datastores, eaters, and service orchestration:
  Improved cleanup and concurrency handling with deterministic regression
  coverage ([@martingalloar](https://github.com/martingalloar)).
- CI, Docker, API documentation, and installation documentation: Modernized
  Python testing and container builds, reduced build dependencies, and aligned
  the documented installation workflow with pysap
  ([@martingalloar](https://github.com/martingalloar)).

### Fixes

- `honeysap/services/forwarder.py` and `honeysap/feeds/dbfeed.py`: Isolated
  forwarded client sessions and normalized persisted event timestamps to UTC
  ([@martingalloar](https://github.com/martingalloar)).
- `honeysap/services/gateway/`: Updated the Gateway service for the current
  pysap RFC interfaces
  ([@martingalloar](https://github.com/martingalloar),
  [#12](https://github.com/OWASP/HoneySAP/pull/12)).
- Dispatcher, SAPRouter, Forwarder, ICM, and Message Server HTTP handlers:
  Fixed lifecycle cleanup, malformed-input handling, response construction,
  and other handler edge cases; expanded socket-free coverage
  ([@martingalloar](https://github.com/martingalloar)).
- `honeysap/services/saprouter/`: Fixed route-table parsing, information
  timestamps, unsupported remote-admin handling, route-port conversion errors,
  and unintended DNS lookups
  ([@martingalloar](https://github.com/martingalloar)).
- Removed the obsolete `six` dependency and Python 2 compatibility imports
  ([@martingalloar](https://github.com/martingalloar)).


## v0.1.2 - unreleased

- Project was contributed by SecureAuth to the OWASP CBAS Project in October 2022.
- Bumped requirements libraries.
- Using Sphinx 1.8.5 for documentation.
- Added GitHub actions to run unit tests.
- Added Docker, Vagrant and Ansible-based deployments.
- Added example internal and external profile configuration files.
- `honeysap/services/dispatcher/`: Added Dispatcher service based on pysap's `SAPDiag` support.
- `honeysap/services/icm/`: Added stub ICM service based on Flask's templates.
- `honeysap/services/messageserver/`: Added Message Server service based on pysap's `SAPMS` support.
- `honeysap/services/saprouter/`: Added Router service based on pysap's `SAPRouter` support.


## v0.1.1 - 2015-10-31

- Initial version released at Troopers '15.
