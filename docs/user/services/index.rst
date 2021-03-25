.. Services chapter frontend

Services
========

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
