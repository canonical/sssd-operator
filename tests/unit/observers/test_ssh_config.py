#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
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

"""Unit tests for the ``SSHConfigObserver`` integration observer."""

import json
from unittest.mock import Mock

import ops
from ops import testing

from charm import SSSDCharm
from constants import LDAP_INTEGRATION_NAME, SSH_CONFIG_INTEGRATION_NAME
from integrations.ssh_config import _SSH_AUTHORIZED_KEYS_CONFIG


class TestSSHConfigObserver:
    """Test the ``ssh-config`` integration event observer."""

    def test_ssh_config_connected(
        self, mock_charm: testing.Context[SSSDCharm], mock_sssd: Mock
    ) -> None:
        """Test the ``_on_ssh_config_connected`` event handler."""
        ldap_relation = testing.Relation(endpoint=LDAP_INTEGRATION_NAME, interface="ldap", id=23)
        ssh_config_relation = testing.Relation(
            endpoint=SSH_CONFIG_INTEGRATION_NAME,
            interface="ssh_config",
            id=24,
            remote_app_name="openssh",
        )

        # Test that the SSH configuration snippet is published to the application
        # databag when the requirer connects.
        mock_sssd.service.is_active.return_value = True
        with mock_charm(
            mock_charm.on.relation_created(ssh_config_relation),
            testing.State(leader=True, relations={ldap_relation, ssh_config_relation}),
        ) as manager:
            state = manager.run()
            assert state.unit_status == ops.ActiveStatus()

            relation = state.get_relation(ssh_config_relation.id)
            # The interface implementation JSON-encodes each dataclass field when
            # writing to the application databag, so compare against the encoded form.
            assert relation.local_app_data["ssh_config"] == json.dumps(_SSH_AUTHORIZED_KEYS_CONFIG)
            assert mock_charm.unit_status_history[1:] == [
                ops.MaintenanceStatus("Publishing SSH configuration")
            ]

    def test_ssh_config_connected_not_leader(
        self, mock_charm: testing.Context[SSSDCharm], mock_sssd: Mock
    ) -> None:
        """Test that only the leader unit publishes SSH configuration data.

        The ``SSHConfigProvider`` implementation only emits
        ``ssh_config_connected`` on the leader unit, so non-leader units must
        not publish data to the application databag.
        """
        ldap_relation = testing.Relation(endpoint=LDAP_INTEGRATION_NAME, interface="ldap", id=23)
        ssh_config_relation = testing.Relation(
            endpoint=SSH_CONFIG_INTEGRATION_NAME,
            interface="ssh_config",
            id=24,
            remote_app_name="openssh",
        )

        mock_sssd.service.is_active.return_value = True
        with mock_charm(
            mock_charm.on.relation_created(ssh_config_relation),
            testing.State(leader=False, relations={ldap_relation, ssh_config_relation}),
        ) as manager:
            state = manager.run()
            relation = state.get_relation(ssh_config_relation.id)
            assert "ssh_config" not in relation.local_app_data
