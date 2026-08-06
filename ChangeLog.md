Changelog
=========

v0.1.3 - 2026-XX-XX
-------------------

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

v0.1.2 - 2022-XX-XX
-------------------

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
