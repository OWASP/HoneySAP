# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# Author:
#   Martin Gallo (@martingalloar)
#   Code contributed by SecureAuth to the OWASP CBAS project
#

import io
import logging
import os
import unittest
from builtins import open as builtin_open
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from honeysap.core.config import Configuration
from honeysap.core.eater import HoneySAPEater
from honeysap.core.honeysap import HoneySAP
from honeysap.core.logger import configure_stream_logger, default_formatter


class EaterOrchestrationTest(unittest.TestCase):

    def setUp(self):
        self.eater = HoneySAPEater()
        self.eater.feed_manager = Mock()

    def test_file_output_is_open_until_stop_and_stdout_is_preserved(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        filename = os.path.join(directory.name, "events.log")
        stdout = io.StringIO()
        self.eater.config = Configuration({"eater_output": ["stdout", "file"],
                                           "eater_filename": filename})

        with patch("honeysap.core.eater.sys.stdout", stdout):
            self.eater.setup_output()
            self.assertFalse(self.eater.outputs[1].closed)
            self.eater.output("event")
            self.eater.stop()
            self.assertTrue(self.eater.outputs[1].closed)
            self.assertFalse(stdout.closed)

        self.assertEqual("event\n", stdout.getvalue())
        with open(filename) as fd:
            self.assertEqual("event\n", fd.read())

    def test_run_stops_feeds_on_normal_return_and_error(self):
        for error in (None, ValueError("consume failed")):
            with self.subTest(error=error):
                self.eater.feed_manager.reset_mock()
                self.eater.feed_manager.consume_events.side_effect = error
                if error:
                    with self.assertRaises(ValueError):
                        self.eater.run()
                else:
                    self.eater.run()
                self.eater.feed_manager.stop.assert_called_once_with()

    def test_owned_output_closes_even_if_feed_stop_fails(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        filename = os.path.join(directory.name, "events.log")
        self.eater.config = Configuration({"eater_output": ["file"],
                                           "eater_filename": filename})
        self.eater.setup_output()
        self.eater.feed_manager.stop.side_effect = RuntimeError("stop failed")
        with self.assertRaises(RuntimeError):
            self.eater.stop()
        self.assertTrue(self.eater.outputs[0].closed)

    def test_setup_output_closes_opened_files_after_later_failure(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        filename = os.path.join(directory.name, "events.log")
        self.eater.config = Configuration({"eater_output": ["file", "file"],
                                           "eater_filename": filename})
        first_output = builtin_open(filename, "a", encoding="utf-8")
        with patch("honeysap.core.eater.open", create=True,
                   side_effect=[first_output, OSError("open failed")]):
            with self.assertRaises(OSError):
                self.eater.setup_output()
        self.assertTrue(first_output.closed)


class HoneySAPOrchestrationTest(unittest.TestCase):

    def test_logger_setup_reuses_honeysap_owned_handler(self):
        logger = logging.getLogger("honeysap.test_logger_setup")
        logger.handlers = []
        first = io.StringIO()
        second = io.StringIO()
        try:
            configure_stream_logger(logger.name, logging.INFO, default_formatter, first)
            configure_stream_logger(logger.name, logging.DEBUG, default_formatter, second)
            handlers = [handler for handler in logger.handlers
                        if getattr(handler, "_honeysap_stream_handler", False)]
            self.assertEqual(len(handlers), 1)
            self.assertIs(handlers[0].stream, second)
            self.assertEqual(handlers[0].level, logging.DEBUG)
        finally:
            logger.handlers = []

    def setUp(self):
        self.honeysap = HoneySAP()
        self.honeysap.config = Configuration({})
        self.honeysap.feed_manager = Mock()
        self.honeysap.service_manager = Mock()

    def test_datastore_is_not_configured_twice(self):
        with patch("honeysap.core.honeysap.DataStoreManager") as manager_type:
            self.honeysap.setup_datastore()
        manager_type.assert_called_once_with(self.honeysap.config)
        self.assertIs(self.honeysap.datastore, manager_type.return_value.get_datastore.return_value)
        self.honeysap.datastore.load_config.assert_not_called()

    def test_run_stops_managers_on_normal_return_and_errors(self):
        for failed_manager in (None, "feed", "service"):
            with self.subTest(failed_manager=failed_manager):
                self.honeysap.feed_manager.reset_mock()
                self.honeysap.service_manager.reset_mock()
                self.honeysap.feed_manager.run.side_effect = None
                self.honeysap.service_manager.run.side_effect = None
                if failed_manager:
                    manager = getattr(self.honeysap, failed_manager + "_manager")
                    manager.run.side_effect = ValueError("run failed")
                    with self.assertRaises(ValueError):
                        self.honeysap.run()
                else:
                    self.honeysap.run()
                self.honeysap.feed_manager.stop.assert_called_once_with()
                self.honeysap.service_manager.stop.assert_called_once_with()

    def test_service_manager_stops_when_feed_stop_fails(self):
        self.honeysap.feed_manager.stop.side_effect = RuntimeError("stop failed")
        with self.assertRaises(RuntimeError):
            self.honeysap.stop()
        self.honeysap.service_manager.stop.assert_called_once_with()
