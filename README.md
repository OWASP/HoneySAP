HoneySAP: SAP Low-interaction honeypot
======================================

Copyright (C) 2015 by Martin Gallo, SecureAuth Corporation

The tool was designed and developed by Martin Gallo from the SecureAuth Corporation's Labs team.

Version 0.1.2.dev0 (XXX 2018)


Overview
--------

HoneySAP is a low-interaction research-focused honeypot specific for SAP
services. It's aimed at learn the techniques and motivations behind attacks
against SAP systems.


Features
--------

- low-interaction honeypot for SAP services
- YAML and JSON-based configuration
- pluggable datastore backend
- modular services system
- modular feeds system
- console logging


Installation
------------

To install HoneySAP, simply download the sources and run:

    $ python setup.py install

A more complete guidance on how to install HoneySAP on different environments
is provided in the documentation.

### Installation with pip ###

Installing honeysap is simple with [pip](https://pip.pypa.io/), just run the
following command on a terminal:

    $ pip install honeysap


License
-------

This tool is distributed under the GPLv2 license. Check the `COPYING` file for
more details.


Contact
-------

Whether you want to report a bug or give some suggestions on this package, drop
us a few lines at `oss@secureauth.com` or contact the author email
`mgallo@secureauth.com`.
