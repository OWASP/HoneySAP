.. Services chapter frontend

Services
========

Choose services according to the interfaces that should be visible to an
attacker. SAPRouter records route, administration, and virtual-service access;
Forwarder exposes or routes bounded TCP relays; ICM and Message Server expose
HTTP and SAP web-tier behavior; Dispatcher and Gateway expose SAP GUI and RFC
protocols. Each service records observations through the same event and feed
flow described in :doc:`../configuration`.

Common configuration options
----------------------------

The following configuration options which are common to all services:

``enabled``:

Whether the service is enable and actually listen to connections.

``listener_address``:

The IP address where the service will be listening to connections.

``listener_port``:

The TCP port where the service will be listening to connections.

``virtual``:

Services in HoneySAP can be configured as *virtual services*. When configured
in such mode, the service is not bind to an actual listener address but
instead listening on a virtual address/port. This is required in order to allow
routing of different services to virtual internal addresses, for example, in the
:doc:`saprouter`.

``alias``:

An alias to provide to the service and differentiate each one.


Common services
---------------

.. toctree::

   forwarder


SAP Services
------------

.. toctree::

   saprouter
   dispatcher
   gateway
   icm
   messageserver
