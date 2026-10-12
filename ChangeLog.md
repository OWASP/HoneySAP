# Changelog

## v0.2.1.dev0 - in dev

### Enhancements and improvements

- `honeysap/core/`: Events carry the raw bytes received and sent on the wire
  instead of a packet summary, plus a `connection_id` per TCP connection
  (event schema version 2). New `logging:` options, global and per service,
  control raw payloads, payload size cap, response and connection events
  ([@randomstr1ng](https://github.com/randomstr1ng)).
- SAP NI services (Dispatcher, Gateway, Message Server, SAPRouter): Added
  `Received packet`, `Sent packet`, `Unparsed input`, and `Connection
  opened`/`Connection closed` events; input that fails to decode or crashes a
  handler is now recorded with its raw bytes instead of being dropped
  ([@randomstr1ng](https://github.com/randomstr1ng)).
- HTTP services (ICM, Message Server HTTP): New HTTP front end reading the
  raw socket. Requests are logged with exact request/response bytes, all
  headers in order, body and multipart parts; non-HTTP input and TLS
  ClientHellos (with JA3/JA4) are logged; one session per connection with the
  real source port. Optional HTTPS listener (`tls:`) with a generated
  SAP-style certificate. Non-HTTP input is answered like the ICM (400 page)
  and Message Server (close). The Message Server HTTP events are now a single
  `MS HTTP request` event with `action`
  ([@randomstr1ng](https://github.com/randomstr1ng)).

- `honeysap/core/persona.py`: New `system:` configuration describing the
  emulated SAP system; Gateway (`RFC_SYSTEM_INFO`), Dispatcher, ICM and
  Message Server report the same identity. `RFCMACH`/`RFCTZONE` are
  right-aligned like on a real system
  ([@randomstr1ng](https://github.com/randomstr1ng)).
- ICM: Responses modeled on an ABAP Platform ICM (header names, case and
  order, error pages, `sap-usercontext` cookie). New ICF service dispatch with
  `/sap/public/ping`, `/sap/public/info`, `/sap/public/icman/ping`, logoff and
  ICM admin redirect; `auth` services answer 401 and log submitted Basic
  credentials (`ICM authentication attempt`). HTTPS mimics the ICM TLS setup
  (certificate chain, TLS 1.2, cipher order), `mimic_icm` to opt out
  ([@randomstr1ng](https://github.com/randomstr1ng)).
- Message Server HTTP: All `/msgserver` commands (application server and
  logon group lists, logon data versions 1.0-1.3, group details) answered
  like the Message Server; other paths redirect with 307. Flask is no longer
  a dependency
  ([@randomstr1ng](https://github.com/randomstr1ng)).

- ICM: SAP Fiori launchpad (`fiori_launchpad`) replayed from a bundle recorded
  on an ABAP Platform system and filled with the system persona: logon page
  and sessions with configurable credentials (`FLP logon attempt` events),
  shell, catalogs, App Finder and apps, OData with CSRF tokens and `$batch`;
  modifying requests are logged and refused. New `static_assets` logging
  option ([@randomstr1ng](https://github.com/randomstr1ng)).

- HTTP services: Request events add decoded query, form and JSON
  parameters, SHA-256 of uploaded files, proxy headers and `tags` for known
  SAP attack patterns (Visual Composer CVE-2025-31324, RECON CVE-2020-6287,
  request smuggling, path traversal, ...); credentials sent as parameters on
  any path produce `HTTP credentials submitted` events. New `http_params`
  logging option ([@randomstr1ng](https://github.com/randomstr1ng)).

### Bug fixes

- Virtual HTTP services no longer bind sockets, so `profiles/external.yml`
  starts without the virtual addresses being local
  ([@randomstr1ng](https://github.com/randomstr1ng)).

## v0.2.0 - 2026-10-06

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
  ([@martingalloar](https://github.com/martingalloar),
  [#13](https://github.com/OWASP/HoneySAP/pull/13)).

### Enhancements and improvements

- Deployment: Deprecated the Vagrant and Ansible definitions; Docker Compose is
  the supported self-contained deployment path
  ([@martingalloar](https://github.com/martingalloar),
  [#14](https://github.com/OWASP/HoneySAP/pull/14)).
- `honeysap/core/`: Added bounded event and per-feed queues, session expiry
  and campaign correlation, versioned event metadata, safe YAML loading,
  redacted configuration logging, and bounded DataStore visibility
  ([@martingalloar](https://github.com/martingalloar),
  [#14](https://github.com/OWASP/HoneySAP/pull/14)).
- Core configuration, feeds, services, and datastores: Isolated component
  configuration, bounded watcher dispatch, added feed retry backoff, improved
  parse diagnostics, and tightened service shutdown
  ([@martingalloar](https://github.com/martingalloar)
  [#13](https://github.com/OWASP/HoneySAP/pull/13)).
- Core service startup: Added service-topology validation and moved gevent
  monkey-patching to the command entrypoints
  ([@martingalloar](https://github.com/martingalloar),
  [#14](https://github.com/OWASP/HoneySAP/pull/14)).
- `honeysap/services/dispatcher/`: Build Dispatcher passports with pysap's
  EPP implementation instead of manually constructing the structure
  ([@martingalloar](https://github.com/martingalloar)).
- `honeysap/services/saprouter/`: Improved control replies, route validation,
  request limits, deny and permitted-target behavior, virtual-service handoff,
  dynamic error counters, and clean routed-client shutdown. Added configurable
  malformed-request behavior and ordered CIDR and SAProuter-style wildcard
  route rules ([@martingalloar](https://github.com/martingalloar),
  [#13](https://github.com/OWASP/HoneySAP/pull/13)).
- `honeysap/core/config.py`: Added relative and nested JSON/YAML includes,
  include-cycle detection, and non-mutating option lookup
  ([@martingalloar](https://github.com/martingalloar)).
- Core feeds, sessions, events, datastores, eaters, and service orchestration:
  Improved cleanup and concurrency handling with deterministic regression
  coverage ([@martingalloar](https://github.com/martingalloar),
  [#14](https://github.com/OWASP/HoneySAP/pull/14)).
- CI, Docker, API documentation, and installation documentation: Modernized
  Python testing and container builds, reduced build dependencies, and aligned
  the documented installation workflow with pysap
  ([@martingalloar](https://github.com/martingalloar),
  [#14](https://github.com/OWASP/HoneySAP/pull/14)).

### Fixes

- `honeysap/services/forwarder.py` and `honeysap/feeds/dbfeed.py`: Isolated
  forwarded client sessions and normalized persisted event timestamps to UTC.
- `honeysap/services/gateway/`: Updated the Gateway service for the current
  pysap RFC interfaces
  ([@martingalloar](https://github.com/martingalloar),
  [#12](https://github.com/OWASP/HoneySAP/pull/12)).
- `honeysap/services/messageserver/` and `honeysap/services/icm/`: Fixed
  Message Server redirection and service integration issues
  ([#11](https://github.com/OWASP/HoneySAP/pull/11)).
- Dispatcher, SAPRouter, Forwarder, ICM, and Message Server HTTP handlers:
  Fixed lifecycle cleanup, malformed-input handling, response construction,
  and other handler edge cases; expanded socket-free coverage.
- `honeysap/services/saprouter/`: Fixed route-table parsing, information
  timestamps, unsupported remote-admin handling, route-port conversion errors,
  and unintended DNS lookups
  ([@martingalloar](https://github.com/martingalloar),
  [#13](https://github.com/OWASP/HoneySAP/pull/13)).
- Removed the obsolete `six` dependency and Python 2 compatibility imports.


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
