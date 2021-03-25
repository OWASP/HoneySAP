HoneySAP: SAP Low-interaction honeypot
======================================

[![Build and test HoneySAP](https://github.com/SecureAuthCorp/HoneySAP/actions/workflows/build_and_test.yml/badge.svg)](https://github.com/SecureAuthCorp/HoneySAP/actions/workflows/build_and_test.yml)
[![Documentation Status](https://readthedocs.org/projects/honeysap/badge/?version=latest)](https://honeysap.readthedocs.io/en/latest/?badge=latest)

SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.

Version 0.1.2.dev0 (XXX 2021)


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


Documentation
-------------

Documentation is available at [Read the Docs](https://honeysap.readthedocs.io/en/latest/).


License
-------

This tool is distributed under the GPLv2 license. Check the `COPYING` file for
more details.


Disclaimer
----------

The spirit of this open source initiative is hopefully to help the community to
alleviate some of the hindrances associated with the implementation of
networking protocols and stacks, aiming at speeding up research and educational
activities. By no means this package is meant to be used in production
environments / commercial products. If so, we would advise to include it into a
proper SDLC process.


Authors
-------

The tool was designed and developed by Martin Gallo from [SecureAuth's Innovation
Labs](https://www.secureauth.com/labs/) team, with the help of many contributors.


Contact
-------

Whether you want to report a bug or give some suggestions on this package, drop
us a few lines at `oss@secureauth.com` or contact the author email
`mgallo@secureauth.com`.
