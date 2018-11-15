#!/usr/bin/env python
# encoding: utf-8
# ===========
# HoneySAP - SAP low-interaction honeypot
#
# Copyright (C) 2015 by Martin Gallo, SecureAuth Corporation
#
# The library was designed and developed by Martin Gallo from
# SecureAuth Corporation's Labs team.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# ==============

# Standard imports
from sys import exit
from os import system
from setuptools import setup, find_packages
# Custom imports
import honeysap


class DocumentationCommand(Command):
    """Custom command for building the documentation with Sphinx.
    """

    description = "Builds the documentation using Sphinx"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        """Runs Sphinx
        """
        exit(system("cd docs && make html"))


setup(name=honeysap.__name__,   # Package information
      version=honeysap.__version__,
      author='Martin Gallo',
      author_email='mgallo@secureauth.com',
      description='SAP low-interaction honeypot',
      long_description=honeysap.__doc__,
      url=honeysap.__url__,
      download_url=honeysap.__url__,
      license=honeysap.__license__,
      classifiers=['Development Status :: 3 - Alpha',
                   'Intended Audience :: Developers',
                   'Intended Audience :: Information Technology',
                   'Intended Audience :: System Administrators',
                   'License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)',
                   'Programming Language :: Python',
                   'Topic :: Security'],
      # Packages list
      packages=find_packages(),
      provides=['honeysap'],

      # Script files
      scripts=['bin/honeysap',
               'bin/honeysapeater'],

      # Tests command
      test_suite='tests.test_suite',

      # Documentation commands
      cmdclass={'doc': DocumentationCommand},

      # Requirements
      install_requires=open('requirements.txt').read().splitlines(),
      dependency_links=["git+https://github.com/rep/hpfeeds.git#egg=hpfeeds"],
      )
