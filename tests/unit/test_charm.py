#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Test default charm events such as upgrade charm, install, etc."""

import unittest
from unittest.mock import patch

from charm import SSSDCharm
from ops.model import ActiveStatus
from ops.testing import Harness


class TestCharm(unittest.TestCase):
    """Unit test sssd charm."""

    def setUp(self) -> None:
        """Set up unit test."""
        self.harness = Harness(SSSDCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    @patch("utils.sssd.start")
    def test_start(self, start) -> None:
        """Test install behavior."""
        self.harness.charm.on.start.emit()
        self.assertEqual(self.harness.charm.unit.status, ActiveStatus())
