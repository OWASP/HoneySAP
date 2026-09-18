.. Installation chapter frontend

Installation
============

This section of the documentation covers the installation process of HoneySAP.
The first step to using it is getting it properly installed on the system.

The following are some basic instructions about how to install HoneySAP on different environments.


Using pip
---------

HoneySAP requires Python 3.10 or newer. After checking out the source,
create an isolated environment and install the package there::

    python3 -m venv .venv
    .venv/bin/python -m pip install --upgrade pip
    .venv/bin/python -m pip install .

The current package requires a compatible development version of ``pysap``.
If it is not available from the configured package index, install ``pysap``
from its source repository in the same environment before installing HoneySAP.


Ubuntu 24.04
------------

Install the Python 3 runtime and virtual-environment support used by the
Docker image::

   sudo apt-get update
   sudo apt-get install git python3 python3-venv

Then install HoneySAP into a virtual environment::

   cd /opt
   git clone https://github.com/OWASP/HoneySAP.git honeysap
   cd /opt/honeysap
   python3 -m venv .venv
   .venv/bin/python -m pip install --upgrade pip
   .venv/bin/python -m pip install "git+https://github.com/OWASP/pysap.git"
   .venv/bin/python -m pip install .

Run it from the source directory so relative profile paths resolve::

   .venv/bin/honeysap --config-file profiles/internal.yml
