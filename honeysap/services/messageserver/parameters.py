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

"""Profile parameters reported by the Message Server HTTP ``parameter``
command, as an ABAP Platform 2025 ASCS instance reports them.

Values hold ``{name}`` fields filled from the system persona and the
Message Server instance; parameters not listed are answered "not found"
like unset parameters on a real system."""

# Standard imports
import hashlib
import uuid
# External imports
# Custom imports


DEFAULT_PARAMETERS = {
    # Instance and directories
    "SAPSYSTEMNAME": "{sid}",
    "SAPSYSTEM": "{ms_instno}",
    "INSTANCE_NAME": "ASCS{ms_instno}",
    "SAPLOCALHOST": "{hostname}",
    "SAPLOCALHOSTFULL": "{fqdn}",
    "SAPGLOBALHOST": "{hostname}",
    "SAPDBHOST": "{db_host}",
    "SAPFQDN": "{domain}",
    "SAPJVM_VERSION": "",
    "SAPPROFILE": "/usr/sap/{sid}/SYS/profile/{sid}_ASCS{ms_instno}_{hostname}",
    "SAPPROFILE_IN_EFFECT": "/usr/sap/{sid}/SYS/profile/{sid}_ASCS{ms_instno}_{hostname}",
    "DIR_INSTANCE": "/usr/sap/{sid}/ASCS{ms_instno}",
    "DIR_EXECUTABLE": "/usr/sap/{sid}/ASCS{ms_instno}/exe",
    "DIR_LIBRARY": "/usr/sap/{sid}/ASCS{ms_instno}/exe",
    "DIR_HOME": "/usr/sap/{sid}/ASCS{ms_instno}/work",
    "DIR_GLOBAL": "/usr/sap/{sid}/SYS/global",
    "DIR_PROFILE": "/usr/sap/{sid}/SYS/profile",
    "DIR_TRANS": "/usr/sap/trans",
    "SETENV_00": "DIR_LIBRARY=/usr/sap/{sid}/ASCS{ms_instno}/exe",
    "OS_UNICODE": "uc",
    "PHYS_MEMSIZE": "23515",
    "exe/saposcol": "/usr/sap/{sid}/ASCS{ms_instno}/exe/saposcol",
    "system/type": "ABAP",
    "system/uuid": "{system_uuid}",
    "system/secure_communication": "OFF",
    # Database
    "dbms/type": "{db_type}",
    "dbs/hdb/dbname": "HDB",
    "dbs/hdb/schema": "SAP{sid}",
    "j2ee/dbname": "",
    # Dispatcher and memory
    "rdisp/myname": "{hostname}_{sid}_{ms_instno}",
    "rdisp/mshost": "{hostname}",
    "rdisp/msserv": "sapms{sid}",
    "rdisp/msserv_internal": "39{ms_instno}",
    "rdisp/sna_gateway": "",
    "rdisp/sna_gw_service": "",
    "rdisp/wp_no_dia": "2",
    "rdisp/wp_no_btc": "0",
    "rdisp/TRACE": "1",
    "rdisp/gui_auto_logout": "3600",
    "rdisp/call_system": "1",
    "abap/heap_area_dia": "2000000000",
    "abap/heap_area_total": "4000000000",
    "em/initial_size_MB": "18812",
    "alert/MONI_SEGM_SIZE": "60000000",
    # Logon and passwords
    "login/system_client": "{client}",
    "login/min_password_lng": "10",
    "login/min_password_diff": "3",
    "login/min_password_digits": "1",
    "login/min_password_letters": "1",
    "login/min_password_lowercase": "1",
    "login/min_password_uppercase": "1",
    "login/min_password_specials": "0",
    "login/fails_to_user_lock": "5",
    "login/failed_user_auto_unlock": "0",
    "login/no_automatic_user_sapstar": "1",
    "login/disable_cpic": "0",
    "login/disable_multi_gui_login": "0",
    "login/disable_password_logon": "0",
    "login/multi_login_users": "",
    "login/password_logon_usergroup": "",
    "login/password_hash_algorithm": "encoding=RFC2307, algorithm=iSSHA-1, iterations=15000, "
                                     "saltsize=128",
    "login/password_downwards_compatibility": "0",
    "login/password_change_for_SSO": "1",
    "login/password_expiration_time": "0",
    "login/password_max_idle_initial": "0",
    "login/password_max_idle_productive": "0",
    "login/server_logon_restriction": "0",
    "login/accept_sso2_ticket": "0",
    "login/create_sso2_ticket": "0",
    "login/ticket_only_by_https": "0",
    "login/ticket_expiration_time": "8:00",
    # Authorizations and audit
    "auth/new_buffering": "4",
    "auth/rfc_authority_check": "1",
    "auth/check/calltransaction": "2",
    "auth/no_check_in_some_cases": "Y",
    "auth/object_disabling_active": "Y",
    "auth/tcodes_not_checked": "",
    "rsau/enable": "1",
    "rsau/integrity": "1",
    "rsau/selection_slots": "10",
    "rsau/user_selection": "1",
    "rec/client": "OFF",
    "csi/enable": "1",
    "csi/exception": "",
    "sapgui/user_scripting": "FALSE",
    "sec/ral_enabled_for_rfc": "0",
    "rfc/callback_security_method": "1",
    "ucon/rfc/active": "0",
    "ucon/rfc/check_blacklist": "1",
    "ucon/websocketrfc/active": "1",
    "ucon/http/cloud_active": "0",
    "service/admin_groups": "",
    "service/admin_users": "",
    "service/hostname": "",
    "service/protectedwebmethods": "SDEFAULT",
    # Gateway
    "gw/acl_file": "",
    "gw/acl_mode": "1",
    "gw/acl_mode_proxy": "0",
    "gw/alternative_hostnames": "",
    "gw/monitor": "1",
    "gw/prxy_info": "/usr/sap/{sid}/ASCS{ms_instno}/data/prxyinfo",
    "gw/reg_info": "/usr/sap/{sid}/ASCS{ms_instno}/data/reginfo",
    "gw/sec_info": "/usr/sap/{sid}/SYS/global/secinfo",
    "gw/reg_no_conn_info": "1",
    "gw/sim_mode": "0",
    "gw/rem_start": "DISABLED",
    "gw/max_conn": "2000",
    "gw/close_routes": "120",
    "gw/accept_remote_trace_level": "0",
    "gw/logging": "ACTION=SsMPXZ LOGFILE=gw_log-%y-%m-%d SWITCHTF=day MAXSIZEKB=200",
    # ICM and ICF
    "icm/server_port_0": "PROT=HTTP,PORT=0,TIMEOUT=60,PROCTIMEOUT=600",
    "icm/server_port_1": "PROT=SMTP,PORT=0,TIMEOUT=120,PROCTIMEOUT=120",
    "icm/host_name_full": "",
    "icm/HTTP/admin_0": "PREFIX=/sap/admin,DOCROOT=/usr/sap/{sid}/ASCS{ms_instno}/data/icmandir/"
                        "admin,AUTHFILE=/usr/sap/{sid}/SYS/global/security/data/icmauth.txt",
    "icm/HTTP/auth_0": "PREFIX=/,FILTER=SAP",
    "icm/HTTP/mod_0": "PREFIX=/",
    "icm/HTTP/allow_invalid_host_header": "FALSE",
    "icm/HTTP/samesite": "None",
    "icm/HTTP/ssl_debug_info": "FALSE",
    "icm/HTTP/ASJava/disable_url_session_tracking": "TRUE",
    "icm/HTTP/logging_0": "PREFIX=/,LOGFILE=/usr/sap/{sid}/ASCS{ms_instno}/log/http-%y-%m-%d.log%z,"
                          "MAXFILES=7,MAXSIZEKB=100000,SWITCHTF=day,LOGFORMAT=DEFAULT",
    "icm/HTTP/logging_client_0": "PREFIX=/,LOGFILE=/usr/sap/{sid}/ASCS{ms_instno}/log/"
                                 "http-client-%y-%m-%d.log%z,MAXFILES=7,MAXSIZEKB=50000,"
                                 "SWITCHTF=day,LOGFORMAT=DEFAULT",
    "icm/HTTPS/verify_client": "1",
    "icm/HTTPS/client_sni_enabled": "TRUE",
    "icm/security_log": "LOGFILE=/usr/sap/{sid}/ASCS{ms_instno}/log/dev_icm_sec-%y-%m-%d%z,"
                        "LEVEL=3,MAXFILES=7,MAXSIZEKB=50000,SWITCHTF=day",
    "icf/cors_enabled": "0",
    "icf/set_HTTPonly_flag_on_cookies": "3",
    "icf/user_recheck": "1",
    "icf/reject_expired_passwd": "0",
    "is/HTTP/sensitive_cookies": "",
    "is/HTTP/sensitive_headers": "",
    "is/HTTP/default_root_hdl": "j2ee",
    "is/HTTP/show_detailed_errors": "FALSE",
    "is/local_addr": "",
    "http/security_session_timeout": "1800",
    # Message Server
    "ms/acl_info": "/usr/sap/{sid}/SYS/global/ms_acl_info",
    "ms/admin_port": "0",
    "ms/monitor": "0",
    "ms/audit": "1",
    "ms/comment": "message server {sid}",
    "ms/http_port": "{ms_http_port}",
    "ms/https_port": "",
    "ms/server_port_0": "PROT=HTTP,PORT={ms_http_port},TIMEOUT=20,PROCTIMEOUT=60",
    "ms/http_logging": "PREFIX=/,LOGFILE=/usr/sap/{sid}/ASCS{ms_instno}/log/ms-http-%y-%m-%d.log%o,"
                       "MAXFILES=7,MAXSIZEKB=10000,SWITCHTF=day,LOGFORMAT=%t %a %u %r %s %b %{{Host}}i",
    "ms/keepalive": "300",
    "ms/max_clients": "600",
    "ms/redirect_version": "1",
    "ms/standalone": "1",
    # SNC and SSL
    "snc/enable": "0",
    "snc/accept_insecure_cpic": "U",
    "snc/accept_insecure_gui": "U",
    "snc/accept_insecure_rfc": "U",
    "snc/accept_insecure_r3int_rfc": "1",
    "snc/data_protection/max": "3",
    "snc/data_protection/min": "3",
    "snc/data_protection/use": "3",
    "snc/force_login_screen": "0",
    "snc/gssapi_lib": "",
    "snc/identity/as": "",
    "snc/r3int_rfc_qop": "8",
    "snc/r3int_rfc_secure": "0",
    "spnego/enable": "0",
    "sec/libsapsecu": "/usr/sap/{sid}/ASCS{ms_instno}/exe/libsapcrypto.so",
    "ssf/name": "SAPSECULIB",
    "ssf/ssfapi_lib": "/usr/sap/{sid}/ASCS{ms_instno}/exe/libsapcrypto.so",
    "ssl/ssl_lib": "/usr/sap/{sid}/ASCS{ms_instno}/exe/libsapcrypto.so",
    "ssl/ciphersuites": "135:PFS:HIGH::EC_P256:EC_HIGH",
    "ssl/client_ciphersuites": "150:PFS:HIGH::EC_P256:EC_HIGH",
}


def system_uuid(persona):
    """Random looking (version 4) UUID that stays the same for a persona"""
    digest = hashlib.sha256(("%s/%s/%s" % (persona.sid, persona.hostname,
                                           persona.machine_id)).encode("utf-8")).digest()
    return str(uuid.UUID(bytes=digest[:16], version=4))


def profile_parameters(persona, ms_instance, ms_http_port, overrides=None):
    """Parameter values for a Message Server instance. ``overrides`` set
    or replace parameters; a value of None removes one."""
    domain = persona.domain or ""
    fields = {"sid": persona.sid, "hostname": persona.hostname,
              "fqdn": "%s.%s" % (persona.hostname, domain) if domain else persona.hostname,
              "domain": domain, "db_host": persona.db_host or persona.hostname,
              "db_type": (persona.db_system or "HDB").lower(), "client": persona.client,
              "ms_instno": ms_instance, "ms_http_port": ms_http_port,
              "system_uuid": system_uuid(persona)}
    parameters = {name: value.format(**fields) for name, value in DEFAULT_PARAMETERS.items()}
    for name, value in (overrides or {}).items():
        if value is None:
            parameters.pop(name, None)
        else:
            parameters[name] = str(value)
    return parameters
