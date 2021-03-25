.. SAP Router service frontend

SAP Router service
==================

Implementation of the SAP Router service.


Configuration options
---------------------

``router_version``:

The mayor version of the SAP Router.

``router_version_patch``:

The patch level version of the SAP Router.

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

With:

.. code-block:: yaml

    <action> := allow | deny
    <talk_mode> := raw | ni | any

Target port accepts a range of ports to use. Target address accepts network
ranges as per ``nmap``'s syntaxis if the ``netaddr`` library is present.

Last entry takes precedence and only one action/mode is allowed per IP/port
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

   router_version: 38
   router_version_patch: 4
   external_admin: false
   route_table:
     - allow,any,10.0.0.1,3200-3209,
