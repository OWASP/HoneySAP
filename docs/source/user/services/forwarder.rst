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
