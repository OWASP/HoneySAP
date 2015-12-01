.. Usage chapter frontend

Usage
=====

Command line
------------

The software has some flags that you can provide at start up::

   $ honeysap -h
   Usage: honeysap [options]
   
   Options:
     -h, --help            show this help message and exit
     -c CONFIG_FILE, --config-file=CONFIG_FILE
                           Loads options from file [default: honeysap.yml]
   
     Logging:
       -v, --verbose       set verbosity level [default: 0]
       --colored-console   set colored console [default: False]
       --show-all-logs     if the console should print logs for all namespaces
                           (root logger) [default: False]

Full configuration is provided using a configuration file (``-c`` or
``--config-file`` options). Detailed documentation about the configuration
options is provided in section :doc:`../user/configuration` and
:doc:`../user/services/index`.
