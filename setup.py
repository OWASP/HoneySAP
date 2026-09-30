#!/usr/bin/env python3
# encoding: utf-8
# HoneySAP - SAP low-interaction honeypot
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
#
# Author:
#   Martin Gallo (@martingalloar)
#   Code contributed by SecureAuth to the OWASP CBAS project
#

# Standard imports
import re
from pathlib import Path
from setuptools import setup, find_packages, Command
from setuptools._distutils.errors import DistutilsExecError


def read_metadata(name):
    """Read a package metadata value from honeysap/__init__.py without importing it."""
    with open("honeysap/__init__.py", "r", encoding="utf-8") as fh:
        content = fh.read()
    match = re.search(r"^%s\s*=\s*['\"]([^'\"]+)['\"]" % re.escape(name), content, re.MULTILINE)
    if not match:
        raise RuntimeError("Unable to find %s in honeysap/__init__.py" % name)
    return match.group(1)


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
        """Run Sphinx."""
        try:
            from sphinx.cmd.build import main as sphinx_build
        except ImportError as exc:
            raise DistutilsExecError(
                "Sphinx is required to build the documentation. "
                "Install the docs extra first: python3 -m pip install honeysap[docs]"
            ) from exc

        docs_dir = Path("docs")
        build_dir = docs_dir / "_build"
        argv = [
            "-b", "html",
            "-d", str(build_dir / "doctrees"),
            str(docs_dir),
            str(build_dir / "html"),
        ]
        self.announce("building documentation with Sphinx", level=2)
        status = sphinx_build(argv)
        if status:
            raise DistutilsExecError("Sphinx build failed with status %d" % status)


with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()


setup(name=read_metadata("__title__"),  # Package information
      version=read_metadata("__version__"),
      author='Martin Gallo, OWASP CBAS Project',
      author_email='martin.gallo@gmail.com',
      description='SAP low-interaction honeypot',
      long_description=long_description,
      long_description_content_type="text/markdown",
      url=read_metadata("__url__"),
      download_url=read_metadata("__url__"),
      license=read_metadata("__license__"),
      classifiers=['Development Status :: 3 - Alpha',
                   'Intended Audience :: Developers',
                   'Intended Audience :: Information Technology',
                   'Intended Audience :: System Administrators',
                   'Programming Language :: Python :: 3',
                   'Programming Language :: Python :: 3 :: Only',
                   'Programming Language :: Python :: 3.10',
                   'Programming Language :: Python :: 3.11',
                   'Programming Language :: Python :: 3.12',
                   'Programming Language :: Python :: 3.13',
                   'Programming Language :: Python :: 3.14',
                   'Topic :: Security'],
      python_requires='>=3.10',
      # Packages list
      packages=find_packages(),
      provides=['honeysap'],

      # Script files
      scripts=['bin/honeysap',
               'bin/honeysapeater'],

      # Documentation commands
      cmdclass={'doc': DocumentationCommand},

      # Requirements
      install_requires=open('requirements.txt').read().splitlines(),

      # Optional requirements for docs
      extras_require={"tests": open('requirements-test.txt').read().splitlines(),
                      "docs": open('requirements-docs.txt').read().splitlines()}
      )
