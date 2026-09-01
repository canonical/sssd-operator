#!/usr/bin/env python3
# Copyright 2023-2026 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for the ``LifecycleObserver`` operations observer."""

from unittest.mock import Mock

import ops
from ops import testing

import sssd
from charm import SSSDCharm
from constants import LDAP_INTEGRATION_NAME


class TestLifecycleObserver:
    """Test the lifecycle event observer."""

    def test_install(self, mock_charm: testing.Context[SSSDCharm], mock_sssd: Mock) -> None:
        """Test the ``_on_install`` event handler."""
        # Test `install` hook reaches target state with no errors.
        with mock_charm(mock_charm.on.install(), testing.State()) as manager:
            state = manager.run()
            assert len(state.deferred) == 0
            mock_sssd.install.assert_called_once()

        # Test `install` hook when `sssd` fails to install on machine.
        mock_charm.unit_status_history.clear()
        mock_sssd.install.side_effect = sssd.SSSDOpsError("failed to install sssd")

        with mock_charm(mock_charm.on.install(), testing.State()) as manager:
            state = manager.run()
            assert state.unit_status == ops.BlockedStatus(
                "Failed to install SSSD. See `juju debug-log` for details"
            )
            assert len(state.deferred) == 1
            assert state.deferred[0].name == "install"

    def test_start(self, mock_charm: testing.Context[SSSDCharm], mock_sssd: Mock) -> None:
        """Test the ``_on_start`` event handler."""
        mock_sssd.version.return_value = "2.9.4"
        with mock_charm(mock_charm.on.start(), testing.State()) as manager:
            state = manager.run()
            assert state.unit_status == ops.WaitingStatus(
                f"Waiting for integrations: [`{LDAP_INTEGRATION_NAME}`]"
            )
            assert mock_charm.unit_status_history[1:] == [
                ops.MaintenanceStatus("Initializing SSSD")
            ]
            assert state.workload_version == "2.9.4"
            mock_sssd.service.enable.assert_called_once()
            mock_sssd.config.init.assert_called_once()

    def test_stop(self, mock_charm: testing.Context[SSSDCharm], mock_sssd: Mock) -> None:
        """Test the ``_on_stop`` event handler."""
        with mock_charm(mock_charm.on.stop(), testing.State()) as manager:
            state = manager.run()
            assert state.unit_status == ops.MaintenanceStatus("SSSD removed")
            assert mock_charm.unit_status_history[1:] == [
                ops.MaintenanceStatus("Stopping SSSD"),
                ops.MaintenanceStatus("Removing SSSD"),
            ]
            mock_sssd.service.stop.assert_called_once()
            mock_sssd.config.delete.assert_called_once()
            mock_sssd.remove.assert_called_once_with(purge=True)
