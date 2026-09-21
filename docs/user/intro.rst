.. Introduction chapter frontend

Introduction
============

Objective
---------

HoneySAP is a low-interaction research-focused honeypot specific for SAP
services. The main objective is to allow security professionals, researchers and
organizations learn about the techniques and motivations behind attacks against
SAP systems.

The goals set for this project are:

* Have a specific purpose honeypot for SAP services.
* Be able to identify the behavior of those attacking SAP systems.
* Be flexible and allow deployment of different scenarios.
* Allow easy extension and improvement of the software.


Design principles
-----------------

The main design principles considered when developing the software are:

Extendible
^^^^^^^^^^

It should be easy to extend the honeypot by adding new services, new mechanisms
of sharing the information (feeds) or other components.

Modular
^^^^^^^

Functionality should be implemented in a modular way allowing the plug-in or
plug-out of the different components. Modules should be configurable as much as
possible.

Easy configuration
^^^^^^^^^^^^^^^^^^

Configuration should be as easier as possible in order to allow customization
of the different services and core components.

Easy deployment
^^^^^^^^^^^^^^^

Deployment should be as easier as possible in order to allow developers and
system administrators without extensive knowledge about honeypots or SAP to run
the software in their environments.



Architecture
------------

HoneySAP is coordinated by the ``HoneySAP`` application object. It loads and
scopes configuration, initializes logging and the optional shared DataStore,
then starts the Session, Feed, and Service managers. Services capture attacker
interactions as versioned ``Event`` objects. The SessionManager correlates them
into connection sessions and campaigns, while the FeedManager delivers them to
independent configured feeds without allowing a slow feed to block a service.

The core components are:

* **Configuration** load validated profiles and discover service, feed, and
  data store implementations.
* **Service Manager** validates listener topology and runs the protocol
  honeypots.
* **Session Manager and Event** create bounded, correlated evidence records for
  observed interactions.
* **Feed Manager** dispatches events to independent feed outputs: Log, Console,
  Database, and HPFeeds outputs. HoneySAPEater can consume supported feed inputs
  separately.
* **Data Store** provides an optional, explicitly configured shared state space
  with bounded asynchronous watcher delivery.

The following diagram shows the current component layout:

.. graphviz::

   digraph honeysap_architecture {
     graph [rankdir=TB, bgcolor="transparent", nodesep=0.45, ranksep=0.65,
            pad=0.15];
     node [shape=box, style="rounded,filled", fillcolor="#f7f7f7",
           color="#555555", fontname="Helvetica"];
     edge [color="#555555", fontname="Helvetica", fontsize=9];

     attacker [label="Attacker / scanner", shape=oval, fillcolor="#fff2cc"];
     operator [label="Operator", shape=oval, fillcolor="#d9ead3"];

     subgraph cluster_honeysap {
       label="HoneySAP";
       color="#6fa8dc";
       penwidth=2;
       style="rounded";

       config [label="Configuration\nprofiles and includes", fillcolor="#d9ead3"];
       app [label="Application\norchestrator", fillcolor="#cfe2f3"];
       datastore [label="DataStore\nshared state", fillcolor="#d9ead3"];
       services [label="ServiceManager\ntopology and lifecycle", fillcolor="#cfe2f3"];
       saprouter [label="SAPRouter"];
       dispatcher [label="Dispatcher"];
       gateway [label="Gateway"];
       icm [label="ICM"];
       messageserver [label="Message Server"];
       forwarder [label="Forwarder"];
       sessions [label="SessionManager\nsessions, campaigns, and Event evidence", fillcolor="#cfe2f3"];
       feeds [label="FeedManager\nLog · Console · DB · HPFeeds delivery", fillcolor="#cfe2f3"];
       eater [label="HoneySAPEater\noptional feed consumer", fillcolor="#d9ead3"];

       { rank=same; saprouter; dispatcher; gateway; icm; messageserver; forwarder; }
       { rank=same; services; app; sessions; }
       { rank=same; config; datastore; feeds; eater; }

       services -> app [style=invis, weight=100];
       app -> sessions [style=invis, weight=100];
       config -> datastore [style=invis, weight=100];
       datastore -> feeds [style=invis, weight=100];

       config -> app [dir=back, constraint=false];
       app -> services [constraint=false];
       app -> sessions [constraint=false];
       saprouter -> sessions [label="observations"];
       dispatcher -> sessions;
       gateway -> sessions;
       icm -> sessions;
       messageserver -> sessions;
       forwarder -> sessions;
       sessions -> feeds;
       feeds -> eater [style=dashed, label="supported inputs"];
       services -> datastore [dir=both, style=dashed, label="shared values", constraint=false];
     }

     attacker -> saprouter [label="protocol requests"];
     attacker -> dispatcher;
     attacker -> gateway;
     attacker -> icm;
     attacker -> messageserver;
     attacker -> forwarder;
     config -> operator [dir=back, label="configures"];
     eater -> operator [style=dashed, label="feed consumption"];
   }
