.. Forwarder service frontend

Forwarder service
=================

The forwarder service forwards the traffic to an external address/port. It
can be used for integration with other honeypots as wells as to provide access
to actual services by means of external or virtual addresses.

Configuration options
---------------------

``target_address``:

The destination IP address where the traffic will be forwarded.

``target_port``:

The destination TCP port where the traffic will be forwarded.

``max_connections``:

Maximum simultaneous forwarding relays, shared by directly exposed and
SAPRouter-routed connections (default ``32``). Connections above the limit
are closed. SAPRouter-routed forwarding carries
the router campaign plus a ``parent_session`` field, which gives feeds an
exact join to the accepting SAPRouter session.


Example configuration
---------------------

The following example configuration options sets a Forwarder service to allow
access to an external:

.. code-block:: yaml

   service: ForwarderService
   enabled: yes
   listener_port: 8000

   target_address: 192.168.56.101
   target_port: 8000
