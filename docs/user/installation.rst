.. Installation chapter frontend

Installation
============

This section of the documentation covers the installation process of HoneySAP.
HoneySAP is intended for an isolated research or monitoring environment; do
not expose it from a workstation or network that is not prepared to receive
untrusted SAP protocol traffic.

Choose either a regular Python installation when you want to edit profiles and
code directly, or Docker Compose for a self-contained deployment.


Regular installation
--------------------

HoneySAP requires Python 3.10 or newer, Git, and ``venv`` support. On Ubuntu
24.04, install the base tools first::

   sudo apt-get update
   sudo apt-get install -y git python3 python3-venv

Clone the repository, create an isolated environment, and install the package.
The declared dependencies install the compatible ``pysap`` revision
automatically::

   git clone https://github.com/OWASP/HoneySAP.git
   cd HoneySAP
   python3 -m venv .venv
   .venv/bin/python -m pip install --upgrade pip setuptools wheel
   .venv/bin/python -m pip install .

Start HoneySAP from the checkout so packaged profile includes resolve relative
to the profile directory::

   .venv/bin/honeysap --config-file profiles/internal.yml

Use ``Ctrl-C`` for a foreground run. Review and copy the supplied profiles
before exposing listeners or enabling an external feed; see
:doc:`configuration` for available options.


Docker Compose
--------------

Install Docker Engine and the Docker Compose plugin for your operating system.
From the checkout, build and start the default internal profile::

   docker compose -f deployment/docker-compose.yml up --build -d

The example supplied ``deployment/docker-compose.yml`` publishes the
Dispatcher, Gateway, ICM, and Message Server ports, persists LogFeed output
under ``./logs``, and mounts ``./data`` read-only for catalog data. Inspect the
running service and follow its logs with::

   docker compose -f deployment/docker-compose.yml ps
   docker compose -f deployment/docker-compose.yml logs -f honeysap

Stop the deployment with::

   docker compose -f deployment/docker-compose.yml down

To use a customized profile, copy one of ``profiles/*.yml`` and add a
read-only bind mount plus a matching ``command`` override in a Compose override
file. Do not publish ports that are not required by the scenario.
