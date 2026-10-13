.. SAP Dispatcher service frontend

SAP Dispatcher service
======================

Implementation of the SAP Dispatcher service. It presents a login screen for
users connecting to it through the SAP GUI.

Events
------

Every DIAG request after the login screen is logged with one event; each is
answered with an error message. The event data holds what the request
carries:

- ``okcode``: the OK code field, and ``transaction`` when it starts a
  transaction (``/nSE38`` gives ``SE38``)
- ``events``: UI events (``type``, ``control``, ``data``, ``menu``,
  ``position``), e.g. a function key
- ``fields``: input fields with ``name`` (the dynpro field, e.g.
  ``RSYST-BNAME``), ``text``, ``row``, ``col`` and ``invisible`` for
  password fields
- ``items``: the names of all DIAG items of the request

The event name tells the kind of request: ``Login request sent the client``
(with ``client``, ``user``, ``password`` and ``language`` from the login
fields), ``Enter sent the client``, ``Menu event sent the client``, ``Other
event sent the client`` or ``Request sent the client``. ``Logoff sent the
client`` and ``Windows closed by the client`` (OK code ``/i``) end the
connection.


Configuration options
---------------------

``instance``:

Name of the SAP instance.

``client_no``:

SAP client number (mandant).

``SID``:

SAP instance SID (System ID).

``session_title``:

Title of the SAP GUI session.

``database_version``:

Version of the SAP database.

``kernel_version``:

Version of the SAP kernel.

``kernel_patch_level``:

Patch level of the SAP kernel.


Example configuration
---------------------

The following example configuration options sets a SAP dispatcher service with
the instance name ``NSP`` and client ``001``:

.. code-block:: yaml

   service: SAPDispatcherService
   enabled: yes
   instance: NSP
   SID: 001
   session_title: SAP Netweaver Server
