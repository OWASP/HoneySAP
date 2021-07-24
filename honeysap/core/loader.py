# HoneySAP - SAP low-interaction honeypot
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
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
#   Martin Gallo (@martingalloar) from SecureAuth's Innovation Labs team.
#

# Standard imports
import pkgutil
from os.path import isabs, join, abspath, dirname
from inspect import getmembers, isabstract, isclass
# External imports

# Custom imports
from .logger import Loggeable


class ClassLoader(Loggeable):

    def __init__(self, base_classes, directory):
        super(ClassLoader, self).__init__()
        self.directory = self.build_directory(directory)
        self.base_classes = set(base_classes)

    def build_directory(self, directory):
        # Build the directory upon the root directory if the one provided is
        # not an absolute path
        if not isabs(directory):
            directory = abspath(join(dirname(__file__), "..", "..", directory))
        return directory

    def is_subclass(self, obj):
        bases = self.base_classes.intersection(set(obj.mro())) if hasattr(obj, "mro") else set()
        return isclass(obj) and obj not in self.base_classes and len(bases) > 0 and not(isabstract(obj))

    def load(self):
        self.logger.debug("Looking for modules in %s", self.directory)
        for class_loader, class_modulename, _ in pkgutil.walk_packages([self.directory, ]):
            self.logger.debug("Found module %s", class_modulename)

            class_module = class_loader.find_module(class_modulename).load_module(class_modulename)
            for class_name, actual_class in getmembers(class_module, self.is_subclass):

                self.logger.debug("Found class %s in module %s", class_name, class_modulename)
                yield class_name, actual_class

    def find(self, class_name):
        for (class_name_found, actual_class) in self.load():
            if class_name == class_name_found:
                return actual_class
        return None
