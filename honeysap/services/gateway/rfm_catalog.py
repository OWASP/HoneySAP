# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

"""RFM catalog loader.

Parses a semicolon-delimited CSV export from SAP table TFDIR/FUPARAREF
(one row per parameter) and returns a dict that maps each function module
name to its metadata and parameter list.

Expected CSV header (produced by SAP transaction SE37 / table download):
    FUNCNAME;REMOTE_CALL;UPDATE_TASK;REMOTE_BASXML_SUPPORTED;PARAMCLASS;
    PARAMETER;TABNAME;FIELDNAME;EXID;POSITION;OFFSET;INTLENGTH;DECIMALS;
    DEFAULT;PARAMTEXT;OPTIONAL

The resulting dict is keyed by FUNCNAME and consumed by the gateway service
to build RFC_GET_FUNCTION_INTERFACE responses dynamically.
"""

import csv
import logging

logger = logging.getLogger(__name__)


def load_rfm_catalog(path):
    """Load RFM parameter definitions from a CSV file.

    Returns a dict::

        {
            "FUNCNAME": {
                "remote_call":              str,  # "R", "S", or ""
                "update_task":              str,
                "remote_basxml_supported":  str,
                "params": [
                    {
                        "paramclass": str,  # I/E/T/C/X
                        "parameter":  str,
                        "tabname":    str,
                        "fieldname":  str,
                        "exid":       str,  # SAP type key (C, I, u, h, …)
                        "position":   int,
                        "intlength":  int,
                        "decimals":   int,
                        "paramtext":  str,
                    },
                    ...
                ],
            },
            ...
        }

    Returns an empty dict if the file cannot be read.
    """
    catalog = {}
    param_count = 0

    try:
        with open(path, newline="", encoding="latin-1") as fh:
            reader = csv.DictReader(fh, delimiter=";", quotechar='"', restval="")
            for row in reader:
                funcname = row.get("FUNCNAME", "").strip()
                if not funcname:
                    continue

                if funcname not in catalog:
                    catalog[funcname] = {
                        "remote_call": row.get("REMOTE_CALL", "").strip(),
                        "update_task": row.get("UPDATE_TASK", "").strip(),
                        "remote_basxml_supported": row.get(
                            "REMOTE_BASXML_SUPPORTED", ""
                        ).strip(),
                        "params": [],
                    }

                try:
                    position = int(row.get("POSITION", "0").strip() or "0")
                except ValueError:
                    position = 0
                try:
                    intlength = int(row.get("INTLENGTH", "0").strip() or "0")
                except ValueError:
                    intlength = 0
                try:
                    decimals = int(row.get("DECIMALS", "0").strip() or "0")
                except ValueError:
                    decimals = 0

                catalog[funcname]["params"].append({
                    "paramclass": row.get("PARAMCLASS", "").strip(),
                    "parameter":  row.get("PARAMETER",  "").strip(),
                    "tabname":    row.get("TABNAME",    "").strip(),
                    "fieldname":  row.get("FIELDNAME",  "").strip(),
                    "exid":       row.get("EXID",       "C").strip() or "C",
                    "position":   position,
                    "intlength":  intlength,
                    "decimals":   decimals,
                    "paramtext":  row.get("PARAMTEXT",  "").strip(),
                })
                param_count += 1

    except (OSError, csv.Error) as exc:
        logger.warning("Failed to load RFM catalog from %s: %s", path, exc)
        return {}

    logger.info(
        "Loaded %d function modules (%d parameters) from %s",
        len(catalog), param_count, path,
    )
    return catalog
