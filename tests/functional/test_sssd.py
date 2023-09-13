#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Test sssd functionality."""

import unittest

from utils import sssd


class TestSSSDCharm(unittest.TestCase):
    """Test sssd charm functionality."""

    def setUp(self) -> None:
        """Install sssd."""
        self.sssd = sssd
        if not self.sssd.available():
            self.sssd.install()

    def test_install(self):
        """Validate install."""
        self.assertTrue(self.sssd.available())
        self.sssd.remove()
