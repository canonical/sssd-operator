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

"""Unit tests for the ``LdapObserver`` integration observer."""

import json
from unittest.mock import Mock

import ops
from charms.glauth_k8s.v0.ldap import LdapProviderData
from ops import testing

from charm import SSSDCharm
from constants import CERTIFICATES_TRANSFER_INTEGRATION_NAME, LDAP_INTEGRATION_NAME


class TestLdapObserver:
    """Test the ``ldap`` integration event observer."""

    def test_ldap_ready(self, mock_charm: testing.Context[SSSDCharm], mock_sssd: Mock) -> None:
        """Test the ``_on_ldap_ready`` event handler."""
        receive_ca_cert_relation = testing.Relation(
            endpoint=CERTIFICATES_TRANSFER_INTEGRATION_NAME,
            interface="certificate_transfer",
            id=19,
        )

        ldap_secret_password = "super-secret-bind-password"
        ldap_secret = testing.Secret(tracked_content={"password": ldap_secret_password})
        ldap_remote_app_name = "glauth"
        ldap_remote_app_data = {
            "urls": json.dumps(["ldap://10.0.0.128:3893"]),
            "ldaps_urls": json.dumps([]),
            "base_dn": "dc=ubuntu,dc=com",
            "bind_dn": "cn=app,ou=model,dc=ubuntu,dc=com",
            "bind_password_secret": ldap_secret.id,
            "auth_method": "simple",
            "starttls": "True",
        }
        mock_client_side_provider_data = LdapProviderData(
            **(ldap_remote_app_data | {"bind_password": ldap_secret_password})
        )
        ldap_relation = testing.Relation(
            endpoint=LDAP_INTEGRATION_NAME,
            interface="ldap",
            id=17,
            remote_app_name=ldap_remote_app_name,
            remote_app_data=ldap_remote_app_data,
        )

        # Test `ldap_ready` hook when the bind password secret hasn't been created.
        ldap_relation.remote_app_data.pop("bind_password_secret")

        with mock_charm(
            mock_charm.on.relation_changed(ldap_relation),
            testing.State(relations={ldap_relation}),
        ) as manager:
            manager.run()

        ldap_relation.remote_app_data["bind_password_secret"] = ldap_secret.id
        mock_charm.unit_status_history.clear()
        mock_charm.emitted_events.clear()

        # Test `ldap_ready` hook when starttls is enabled but `certificate_transfer`
        # integration does not exist.
        with mock_charm(
            mock_charm.on.relation_changed(ldap_relation),
            testing.State(relations={ldap_relation}, secrets={ldap_secret}),
        ) as manager:
            state = manager.run()
            assert state.unit_status == ops.WaitingStatus(
                f"Waiting for integrations: [`{CERTIFICATES_TRANSFER_INTEGRATION_NAME}`]"
            )
            assert len(state.deferred) == 1
            assert state.deferred[0].name == "ldap_ready"
            assert len(mock_charm.emitted_events) == 2

        # Test `ldap_ready` hook when the first domain is added.
        mock_charm.unit_status_history.clear()
        mock_charm.emitted_events.clear()
        mock_sssd.config.domains.return_value = []
        mock_sssd.service.is_active.return_value = True

        with mock_charm(
            mock_charm.on.relation_changed(ldap_relation),
            testing.State(
                relations={ldap_relation, receive_ca_cert_relation}, secrets={ldap_secret}
            ),
        ) as manager:
            state = manager.run()
            assert state.unit_status == ops.ActiveStatus()
            assert len(state.deferred) == 0
            assert mock_charm.unit_status_history[1:] == [
                ops.MaintenanceStatus(
                    f"Adding domain `{ldap_remote_app_name}` to SSSD configuration"
                ),
                ops.MaintenanceStatus("Enabling SSSD"),
            ]
            mock_sssd.config.add_ldap_domain.assert_called_once_with(
                ldap_remote_app_name,
                mock_client_side_provider_data,
            )
            mock_sssd.config.update_ldap_domain.assert_not_called()
            mock_sssd.service.enable.assert_called_once()
            mock_sssd.service.restart.assert_not_called()

        # Test `ldap_ready` hook when a second domain is added.
        mock_charm.unit_status_history.clear()
        mock_charm.emitted_events.clear()
        mock_sssd.config.add_ldap_domain.reset_mock()
        mock_sssd.service.enable.reset_mock()
        mock_sssd.config.domains.return_value = [ldap_remote_app_name]
        mock_sssd.service.is_active.return_value = True

        with mock_charm(
            mock_charm.on.relation_changed(ldap_relation),
            testing.State(
                relations={ldap_relation, receive_ca_cert_relation}, secrets={ldap_secret}
            ),
        ) as manager:
            state = manager.run()
            assert state.unit_status == ops.ActiveStatus()
            assert len(state.deferred) == 0
            assert mock_charm.unit_status_history[1:] == [
                ops.MaintenanceStatus(
                    f"Updating domain `{ldap_remote_app_name}` in SSSD configuration"
                ),
                ops.MaintenanceStatus("Restarting SSSD"),
            ]
            mock_sssd.config.add_ldap_domain.assert_not_called()
            mock_sssd.config.update_ldap_domain.assert_called_once_with(
                ldap_remote_app_name,
                mock_client_side_provider_data,
            )
            mock_sssd.service.enable.assert_not_called()
            mock_sssd.service.restart.assert_called_once()

    def test_ldap_unavailable(
        self, mock_charm: testing.Context[SSSDCharm], mock_sssd: Mock
    ) -> None:
        """Test the ``_on_ldap_unavailable`` event handler."""
        ldap_relation = testing.Relation(
            endpoint=LDAP_INTEGRATION_NAME,
            interface="ldap",
            id=21,
            remote_app_name="glauth",
        )
        ldap_relation_2 = testing.Relation(
            endpoint=LDAP_INTEGRATION_NAME,
            interface="ldap",
            id=22,
            remote_app_name="polaris",
        )

        # Test `ldap_unavailable` hook when there's still domains in `sssd.conf`.
        mock_sssd.config.domains.return_value = ["polaris"]
        mock_sssd.service.is_active.return_value = True

        with mock_charm(
            mock_charm.on.relation_broken(ldap_relation),
            testing.State(relations={ldap_relation, ldap_relation_2}),
        ) as manager:
            state = manager.run()
            assert state.unit_status == ops.ActiveStatus()
            assert mock_charm.unit_status_history[1:] == [ops.MaintenanceStatus("Restarting SSSD")]
            mock_sssd.config.remove_ldap_domain.assert_called_once_with("glauth")
            mock_sssd.service.disable.assert_not_called()
            mock_sssd.service.restart.assert_called_once()

        # Test `ldap_unavailable` hook when there's no more domains in `sssd.conf`.
        mock_charm.unit_status_history.clear()
        mock_sssd.config.remove_ldap_domain.reset_mock()
        mock_sssd.service.restart.reset_mock()
        mock_sssd.config.domains.return_value = []
        mock_sssd.service.is_active.return_value = False

        with mock_charm(
            mock_charm.on.relation_broken(ldap_relation),
            testing.State(relations={ldap_relation}),
        ) as manager:
            state = manager.run()
            assert state.unit_status == ops.WaitingStatus(
                f"Waiting for integrations: [`{LDAP_INTEGRATION_NAME}`]"
            )
            assert mock_charm.unit_status_history[1:] == [ops.MaintenanceStatus("Disabling SSSD")]
            mock_sssd.config.remove_ldap_domain.assert_called_once_with("glauth")
            mock_sssd.service.disable.assert_called_once()
            mock_sssd.service.restart.assert_not_called()
