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
import os
import json
from pprint import pformat
from os.path import isfile
from abc import abstractmethod, ABCMeta
from optparse import OptionParser, Values
# External imports
# Optional imports
try:
    from yaml import SafeLoader as yaml_loader
except ImportError:
    yaml_loader = None

try:
    from jsoncomment import JsonComment as json_comment
except ImportError:
    json_comment = None


class ConfigurationParserNotFound(Exception):
    """Configuration file parser not found"""


class ConfigurationIncludeError(ValueError):
    """Configuration include is outside the configured root."""


class ConfigurationFileParser(object, metaclass=ABCMeta):

    def __init__(self):
        self._config_files = []

    @abstractmethod
    def check_file(self, config_file):
        """Checks if the parser can parse a configuration file """

    @abstractmethod
    def parse_file(self, config_file):
        """Parses the configuration file and return the options obtained """


class ConfigurationJSONParser(ConfigurationFileParser):
    """Parse configuration file from JSON"""

    include_string = "!include"

    def object_hook(self, inp):
        """Resolve include objects relative to the file containing them."""
        if self.include_string in inp:
            include = inp[self.include_string]
            if not isinstance(include, str):
                raise ValueError("JSON include path must be a string")
            filename = self._included_filename(include)
            self._config_files.append(filename)
            return self._parse_file(filename)
        return inp

    def check_file(self, config_file):
        """Check if the file is a valid JSON file"""
        try:
            with open(config_file, 'r') as f:
                json.loads(f.read())
        except ValueError:
            return False
        return True

    def parse_file(self, config_file):
        """Parses the JSON configuration file"""
        self._config_files = []
        self._active_files = set()
        filename = os.path.abspath(config_file)
        self._include_root = os.path.dirname(filename)
        return Configuration(self._parse_file(filename))

    def _included_filename(self, include):
        filename = os.path.abspath(os.path.join(self._root, include))
        if os.path.commonpath((self._include_root, filename)) != self._include_root:
            raise ConfigurationIncludeError("JSON include outside configuration root: %s" % include)
        return filename

    def _parse_file(self, filename):
        if filename in self._active_files:
            raise ValueError("Cyclic JSON include: %s" % filename)
        self._active_files.add(filename)
        previous_root = getattr(self, "_root", None)
        self._root = os.path.dirname(filename)
        try:
            with open(filename, 'r') as f:
                return json_comment(json).load(f, object_hook=self.object_hook)
        finally:
            self._root = previous_root
            self._active_files.remove(filename)


if yaml_loader is not None:
    class ConfigurationYAMLLoader(yaml_loader):
        """Customized YAML loader to use !include inside configuration files"""

        include_string = "!include"

        def __init__(self, stream, active_files=None, include_root=None):
            self._config_files = []
            filename = os.path.abspath(stream.name)
            self._root = os.path.dirname(filename)
            self._include_root = include_root or self._root
            self._active_files = active_files or {filename}
            super(ConfigurationYAMLLoader, self).__init__(stream)
            self.add_constructor(self.include_string, ConfigurationYAMLLoader.include)

        def include(self, node):
            include = self.construct_scalar(node)
            filename = os.path.abspath(os.path.join(self._root, include))
            if os.path.commonpath((self._include_root, filename)) != self._include_root:
                raise ConfigurationIncludeError("YAML include outside configuration root: %s" % include)
            if filename in self._active_files:
                raise ValueError("Cyclic YAML include: %s" % filename)
            self._config_files.append(filename)
            with open(filename, 'r') as f:
                loader = ConfigurationYAMLLoader(f, self._active_files | {filename},
                                                  self._include_root)
                try:
                    config = loader.get_single_data()
                    self._config_files.extend(loader._config_files)
                    return config
                finally:
                    loader.dispose()
else:
    ConfigurationYAMLLoader = None


class ConfigurationYAMLParser(ConfigurationFileParser):
    """Parse configuration file from YAML"""

    def __init__(self, *args, **kwargs):
        super(ConfigurationYAMLParser, self).__init__(*args, **kwargs)

    def check_file(self, config_file):
        """Check if the file is a valid YAML file"""

        # Check if the yaml library is present
        if yaml_loader is None:
            return False

        # Try to parse the file
        try:
            with open(config_file, 'r') as f:
                loader = ConfigurationYAMLLoader(
                    f, include_root=os.path.dirname(os.path.abspath(config_file)))
                try:
                    loader.get_single_data()
                finally:
                    loader.dispose()
        except Exception:
            return False
        return True

    def parse_file(self, config_file):
        """Parses the YAML configuration file"""
        self._config_files = []
        with open(config_file, 'r') as f:
            loader = ConfigurationYAMLLoader(
                f, include_root=os.path.dirname(os.path.abspath(config_file)))
            try:
                config = loader.get_single_data()
                self._config_files.extend(loader._config_files)
            finally:
                loader.dispose()
        return Configuration(config)


class Configuration(Values):
    """Set of configurable options"""

    _options_parsers = [ConfigurationJSONParser(),
                        ConfigurationYAMLParser()]

    def __init__(self, *args, **kwargs):
        Values.__init__(self, *args, **kwargs)
        self._config_files = []

    def __repr__(self):
        return pformat(self.__dict__)

    def __str__(self):
        return pformat(self.__dict__)

    def redacted(self):
        """Return a safe-to-log rendering of configuration values only."""
        sensitive = ("password", "passwd", "secret", "token", "credential",
                     "authorization", "api_key", "access_key", "private_key",
                     "keyfile", "cert", "key", "db_engine")

        def clean(value, key=None):
            if key is not None and any(marker in key.lower() for marker in sensitive):
                return "***REDACTED***"
            if isinstance(value, dict):
                return {name: clean(item, str(name)) for name, item in value.items()
                        if name != "_config_files"}
            if isinstance(value, (list, tuple)):
                return [clean(item) for item in value]
            return value

        return pformat(clean(self.__dict__))

    def __iter__(self):
        return self.__dict__.__iter__()

    def __delitem__(self, item):
        del(self.__dict__[item])

    def update(self, obj, mode="loose", from_file=False):
        if mode == "careful":
            fnc = self._update_careful
        elif mode == "loose":
            fnc = self._update_loose
        else:
            raise ValueError("Invalid configuration update mode: %s" % mode)

        if from_file is True:
            if isinstance(obj, str) and isfile(obj):
                parse_errors = []
                extension = os.path.splitext(obj)[1].lower()
                parsers = self._options_parsers
                if extension == ".json":
                    parsers = [ConfigurationJSONParser()]
                elif extension in (".yaml", ".yml"):
                    parsers = [ConfigurationYAMLParser()]
                for parser in parsers:
                    try:
                        parsed = parser.parse_file(obj)
                    except Exception as error:
                        parse_errors.append(error)
                    else:
                        self.update(parsed, mode)
                        self._config_files.extend(parser._config_files)
                        break
                else:
                    details = "; ".join(str(error) for error in parse_errors
                                        if str(error))
                    raise ConfigurationParserNotFound(
                        "Unable to parse configuration file %s%s" %
                        (obj, ": %s" % details if details else ""))
            else:
                raise ValueError("Invalid configuration file")

            # Add the filename to the list of config files
            self._config_files.append(obj)

        else:
            if isinstance(obj, (dict,)):
                return fnc(obj)
            if hasattr(obj, "__dict__"):
                return fnc(obj.__dict__)

    def config_for(self, category, name, classname):
        config = []

        if category not in self:
            return config

        for item in getattr(self, category):
            if name in item and item[name] == classname:
                item_config = Configuration()
                item_config.update(self._component_defaults(category))
                item_config.update(item)
                del(item_config["_config_files"])
                config.append(item_config)
        return config

    def _component_defaults(self, category):
        """Return the configuration defaults appropriate for one component."""
        scoped = {key: value for key, value in self.__dict__.items()
                  if key not in ("_config_files", "services", "feeds", "datastore")}
        if category == "services":
            allowed = {"service", "alias", "enabled", "virtual",
                       "listener_address", "listener_port", "release",
                       "hostname", "instance"}
            scoped["services"] = [{key: value for key, value in service.items()
                                   if key in allowed}
                                  for service in self.get("services", [])]
        return scoped

    def get(self, option, default=None):
        return self.__dict__.get(option, default)

    def get_config_files(self):
        return self._config_files


class ConfigurationParserFromFile(OptionParser):

    def __init__(self, **kwargs):
        """Initializes the configuration parser"""
        default_config = kwargs.pop("default_config", None)
        OptionParser.__init__(self, **kwargs)
        self.add_option("-c", "--config-file",
                        action="store",
                        dest="config_file",
                        help="Loads options from file [default: %default]",
                        default=default_config)

    def parse_args(self, args=None, values=None):
        """Parses some arguments and returns a Configuration instance"""
        (values, args) = OptionParser.parse_args(self, args=args, values=values)

        configuration = Configuration()
        configuration.update(values)

        if configuration.config_file:
            configuration.update(configuration.config_file, from_file=True)

        return configuration, args
