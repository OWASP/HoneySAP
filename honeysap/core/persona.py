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

"""The SAP system all services pretend to be.

Services read the identity of the emulated system (SID, host, instance,
release, ...) from the top-level ``system:`` mapping so that every protocol
reports the same values. Service options with the historic names (e.g.
``hostname`` or ``sid``) still override the shared values."""

# Standard imports
from html import escape
# External imports
# Custom imports


class SystemPersona(object):

    defaults = {
        "sid": "PRD",
        "hostname": "sapnw702",
        # DNS domain, used for the TLS certificate name (<SID>.<domain>)
        "domain": None,
        "instance_number": "00",
        "client": "001",
        "language": "EN",
        # SAP_BASIS release (RFCSAPRL) and kernel release (RFCKERNRL)
        "release": "816",
        "kernel_release": "916",
        "db_system": "HDB",
        # Database host, defaults to the hostname
        "db_host": None,
        "os": "Linux",
        # Address reported by the system, defaults to the address the client
        # connected to
        "ip_address": None,
        # Timezone offset from UTC in seconds (RFCTZONE)
        "timezone_offset": 0,
        "machine_id": "390",
    }

    # Historic service options mapped to persona fields
    service_aliases = {
        "sid": "sid",
        "hostname": "hostname",
        "instance_number": "instance_number",
        "client_no": "client",
        "client": "client",
        "db_system": "db_system",
        "os_name": "os",
        "sap_release": "release",
    }

    def __init__(self, **values):
        unknown = set(values) - set(self.defaults)
        if unknown:
            raise ValueError("Unknown system option(s): %s" % ", ".join(sorted(unknown)))
        merged = dict(self.defaults)
        merged.update({key: value for key, value in values.items() if value is not None})
        for key in ("sid", "hostname", "instance_number", "client", "language",
                    "release", "kernel_release", "db_system", "os", "machine_id"):
            merged[key] = str(merged[key])
        merged["instance_number"] = merged["instance_number"].zfill(2)
        merged["language"] = merged["language"].upper()
        self.__dict__.update(merged)
        if not self.db_host:
            self.db_host = self.hostname

    @classmethod
    def from_config(cls, config):
        """Build the persona for a service configuration: the ``system:``
        mapping overridden by the historic options (``hostname``, ``sid``,
        ...) set globally or on the service."""
        values = dict(config.get("system") or {})
        for option, field in cls.service_aliases.items():
            value = config.get(option)
            if value is not None:
                values[field] = value
        return cls(**values)

    @property
    def certificate_name(self):
        """Common name of the system certificate: <SID>.<domain> like an
        installation certificate, or the hostname without a domain."""
        if self.domain:
            return "%s.%s" % (self.sid, self.domain)
        return self.hostname

    @property
    def instance_name(self):
        """Application server instance name, e.g. sapnw702_PRD_00."""
        return "%s_%s_%s" % (self.hostname, self.sid, self.instance_number)

    def address(self, local_address=None):
        if self.ip_address:
            return str(self.ip_address)
        if local_address and local_address not in ("0.0.0.0", "::", ""):
            return local_address
        return "127.0.0.1"

    def rfcsi(self, local_address=None):
        """RFCSI structure values (RFC_SYSTEM_INFO), formatted like a real
        system (fixed widths, right-aligned numbers)."""
        address = self.address(local_address)
        return [
            ("RFCPROTO", "011"),
            ("RFCCHARTYP", "4103"),
            ("RFCINTTYP", "LIT"),
            ("RFCFLOTYP", "IE3"),
            ("RFCDEST", self.instance_name),
            ("RFCHOST", self.hostname[:8]),
            ("RFCSYSID", self.sid),
            ("RFCDATABS", self.sid),
            ("RFCDBHOST", self.db_host),
            ("RFCDBSYS", self.db_system),
            ("RFCSAPRL", self.release),
            ("RFCMACH", self.machine_id.rjust(5)),
            ("RFCOPSYS", self.os),
            ("RFCTZONE", str(int(self.timezone_offset)).rjust(6)),
            ("RFCDAYST", ""),
            ("RFCIPADDR", address),
            ("RFCKERNRL", self.kernel_release),
            ("RFCHOST2", self.hostname),
            ("RFCSI_RESV", ""),
            ("RFCIPV6ADDR", address),
        ]

    def rfc_system_info_xml(self, local_address=None):
        """The /sap/public/info document: RFC_SYSTEM_INFO as SOAP XML."""
        fields = "".join("<%s>%s</%s>" % (name, escape(value, quote=False), name)
                         for name, value in self.rfcsi(local_address))
        return ('<?xml version="1.0" encoding="UTF-8"?>'
                '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
                '<SOAP-ENV:Body><rfc:RFC_SYSTEM_INFO.Response '
                'xmlns:rfc="urn:sap-com:document:sap:rfc:functions"><RFCSI>%s</RFCSI>'
                '</rfc:RFC_SYSTEM_INFO.Response></SOAP-ENV:Body></SOAP-ENV:Envelope>' % fields)
