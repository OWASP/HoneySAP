.. Installation chapter frontend

Installation
============

This section of the documentation covers the installation process of HoneySAP.
The first step to using it is getting it properly installed on the system.

The following are some basic instructions about how to install HoneySAP on different environments. 


Using pip
---------

Installing honeysap is simple with pip, just run the following command on a terminal::

    pip install honeysap


Ubuntu 14.04
------------

First step would be to install system packages that are required::

   sudo apt-get update && sudo apt-get install git python-pip python-dev build-essentials

After having all the system packages ready, you can proceed to install HoneySAP::

   cd /opt
   git clone https://github.com/CoreSecurity/honeysap
   cd honeysap
   sudo python setup.py install

The setup should take care of all python packages that are required, with only one exception
that need to be installed manually::

   sudo pip install "git+https://github.com/rep/hpfeeds.git#egg=hpfeeds"

The honeypot is then ready for being run::

   /usr/local/bin/honesap --config-file /opt/honeysap/honeysap.yml


