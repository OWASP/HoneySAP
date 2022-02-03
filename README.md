HoneySAP: SAP Low-interaction honeypot
======================================

[![Build and test HoneySAP](https://github.com/SecureAuthCorp/HoneySAP/actions/workflows/build_and_test.yml/badge.svg)](https://github.com/SecureAuthCorp/HoneySAP/actions/workflows/build_and_test.yml)
[![Documentation Status](https://readthedocs.org/projects/honeysap/badge/?version=latest)](https://honeysap.readthedocs.io/en/latest/?badge=latest)

SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.

Version 0.1.2.dev0 (XXX 2022)


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

    $ python -m pip install .

A more complete guidance on how to install HoneySAP on different environments
is provided in the documentation.


Documentation
-------------

Documentation is available at [Read the Docs](https://honeysap.readthedocs.io/en/latest/).


License
-------

This tool is distributed under the GPLv2 license. Check the [COPYING](COPYING)
file for more details.


Authors
-------

The tool was designed and developed by Martin Gallo from [SecureAuth's Innovation
Labs](https://www.secureauth.com/labs/) team, with the help of many contributors.

Disclaimer
----------

The spirit of this Open Source initiative is to help security researchers,
and the community, speed up research and educational activities related to
the implementation of networking protocols and stacks.

The information in this repository is for research and educational purposes
and not meant to be used in production environments and/or as part
of commercial products.

If you desire to use this code or some part of it for your own uses, we
recommend applying proper security development life cycle and secure coding
practices, as well as generate and track the respective indicators of
compromise according to your needs.


Contact Us
----------

Whether you want to report a bug, send a patch, or give some suggestions
on this package, drop us a few lines at oss@secureauth.com.

For security-related questions check our [security policy](SECURITY.md).
