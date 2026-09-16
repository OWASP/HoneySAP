Changelog
=========

v0.2.0.dev0 (unreleased)
-------------------

- `honeysap/services/saprouter`: Significantly enhanced SAP Router services.
  - Improved SAPRouter control, route validation, timeout, denial, and
    permitted-target replies, including NI-framed virtual-service handoff and
    process-dynamic error counters and clean routed-client shutdown with older
    pysap releases. Version-specific error text, metadata, and counter steps
    can now be overridden per service with `error_profile`, with a default
    baseline and validated standalone profile examples for reference builds;
    service definitions can import reusable error-profile YAML fragments.
    Build identity no longer selects hard-coded response definitions.
  - Matched the newest malformed-route length, old-version, empty/unknown host,
    invalid-service, and oversized-request branches with configurable errors;
    prevented uncaught route-port conversion errors and unintended DNS lookups.
  - Made SAPRouter NI request-size and unknown-packet behavior profile settings.
  - Matched ordered CIDR and SAProuter-style wildcard route rules without
    expanding large tables into connected clients; enabled raw virtual
    Forwarder handoff, corrected information timestamps, and denied unsupported
    remote-admin commands.
- Hardened configuration includes: relative and nested JSON/YAML includes,
  cycle detection, and non-mutating option lookup.
- Improved feed, session, event, datastore, and eater cleanup and concurrency;
  added deterministic regression coverage for these core paths.
- Fixed service lifecycle cleanup and handler edge cases in Dispatcher,
  SAPRouter, Forwarder, ICM, and Message Server HTTP; expanded socket-free tests.
- Modernized Python 3 test and Docker workflows and refreshed the documented
  installation path.

- `honeysap/services/gateway/`: Significantly enhanced SAP RFC Gateway service.
  - Full NWRFC SDK handshake: responds to `RFC_SYSTEM_INFO`, `RFC_GET_FUNCTION_INTERFACE`,
    and `DDIF_FIELDINFO_GET` with catalog-driven or synthetic responses.
  - RFM catalog support: `rfm_catalog` CSV (exported via `Z_HONEYSAP_EXPORT`) drives
    accurate parameter-interface responses for any known function module.
  - DDIC catalog support: `ddic_catalog` CSV provides exact field layouts for
    `DDIF_FIELDINFO_GET`, including nested internal table types (TTYP), correct
    NUC/UC size arithmetic, and LINES_DESCR XML generation.
  - Credential capture: SAP logon user, client, XOR-descrambled password, client IP,
    hostname, OS username (CPI-C field; 12-byte limit flagged in events).
  - XML parameter logging: NWRFC SDK wire-encoded XML for table/structure parameters
    is extracted and logged inline for all business function calls.
  - CVE-2025-42957 detection: calls to `/SLOAE/DEPLOY` are recognised and the
    injected ABAP code is extracted from `IT_MODULE` and recorded line-by-line.
- `honeysap/services/gateway/rfm_catalog.py`: New module to load RFC function module
  catalog from CSV.
- `honeysap/services/gateway/ddic_catalog.py`: New module to load DDIC structure
  field definitions from CSV, including NUC/UC length normalisation.
- `tools/Z_HONEYSAP_EXPORT.abap`: ABAP report to export both RFM and DDIC catalogs
  from a reference SAP system.

v0.1.2 - (unreleased)
---------------------

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

v0.1.1 - 2015-10-31
-------------------

- Initial version released at Troopers '15.
