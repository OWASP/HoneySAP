.. SAP Dispatcher service frontend

SAP Dispatcher service
======================

Implementation of the SAP Dispatcher service. It presents a login screen for
users connecting to it through the SAP GUI.


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
