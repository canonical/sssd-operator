#!/usr/bin/env python3
# Copyright 2023-2025 Canonical Ltd.
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

"""Unit tests for the sssd charm."""

import json
import unittest

# Must come before `SSSDCharm` import.
import ops
from charms.glauth_k8s.v0.ldap import LdapProviderData
from mock_sssd_module import mock_sssd, reset_mock_sssd_module  # noqa F401
from ops import testing

import sssd
from charm import SSSDCharm
from constants import CERTIFICATES_TRANSFER_INTEGRATION_NAME, LDAP_INTEGRATION_NAME


class TestCharm(unittest.TestCase):
    """Unit tests for the sssd charm."""

    def setUp(self) -> None:
        """Set up unit test."""
        self.ctx = testing.Context(SSSDCharm)

    @reset_mock_sssd_module
    def test_install(self) -> None:
        """Test the `_on_install` hook."""
        # Test `install` hook reaches target state with no errors.
        mock_sssd.version.return_value = "2.9.4-1.1ubuntu6.2"
        with self.ctx(self.ctx.on.install(), testing.State()) as manager:
            state = manager.run()
            self.assertEqual(state.workload_version, sssd.version())
            self.assertEqual(
                state.unit_status,
                ops.WaitingStatus(f"Waiting for integrations: [`{LDAP_INTEGRATION_NAME}`]"),
            )
            self.assertEqual(len(state.deferred), 0)
            self.assertListEqual(
                self.ctx.unit_status_history[1:], [ops.MaintenanceStatus("Installing SSSD")]
            )
            mock_sssd.install.assert_called_once()

        # Test `install` hook when `sssd` fails to install on machine.
        self.ctx.unit_status_history.clear()
        mock_sssd.install.side_effect = sssd.SSSDOpsError("failed to install sssd")

        with self.ctx(self.ctx.on.install(), testing.State()) as manager:
            state = manager.run()
            self.assertEqual(
                state.unit_status,
                ops.BlockedStatus("Failed to install SSSD. See `juju debug-log` for details"),
            )
            self.assertEqual(len(state.deferred), 1)
            self.assertEqual(state.deferred[0].name, "install")
            self.assertListEqual(
                self.ctx.unit_status_history[1:], [ops.MaintenanceStatus("Installing SSSD")]
            )

    @reset_mock_sssd_module
    def test_stop(self) -> None:
        """Test the `_on_stop` hook."""
        with self.ctx(self.ctx.on.stop(), testing.State()) as manager:
            state = manager.run()
            self.assertEqual(state.unit_status, testing.MaintenanceStatus("SSSD removed"))
            self.assertListEqual(
                self.ctx.unit_status_history[1:],
                [
                    ops.MaintenanceStatus("Disabling SSSD"),
                    ops.MaintenanceStatus("Removing SSSD"),
                ],
            )
            mock_sssd.disable.assert_called_once()
            mock_sssd.remove.assert_called_once()

    @reset_mock_sssd_module
    def test_ldap_ready(self) -> None:
        """Test the `_on_ldap_ready` hook."""
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

        with self.ctx(
            self.ctx.on.relation_changed(ldap_relation),
            testing.State(relations={ldap_relation}),
        ) as manager:
            manager.run()

        ldap_relation.remote_app_data["bind_password_secret"] = ldap_secret.id
        self.ctx.unit_status_history.clear()
        self.ctx.emitted_events.clear()

        # Test `ldap_ready` hook when starttls is enabled but `certificate_transfer`
        # integration does not exist.
        with self.ctx(
            self.ctx.on.relation_changed(ldap_relation),
            testing.State(relations={ldap_relation}, secrets={ldap_secret}),
        ) as manager:
            state = manager.run()
            self.assertEqual(
                state.unit_status,
                ops.WaitingStatus(
                    f"Waiting for integrations: [`{CERTIFICATES_TRANSFER_INTEGRATION_NAME}`]"
                ),
            )
            self.assertEqual(len(state.deferred), 1)
            self.assertEqual(state.deferred[0].name, "ldap_ready")
            self.assertEqual(len(self.ctx.emitted_events), 2)

        # Test `ldap_ready` hook when the first domain is added.
        self.ctx.unit_status_history.clear()
        self.ctx.emitted_events.clear()
        mock_sssd.domains.return_value = []
        mock_sssd.active.return_value = True

        with self.ctx(
            self.ctx.on.relation_changed(ldap_relation),
            testing.State(
                relations={ldap_relation, receive_ca_cert_relation}, secrets={ldap_secret}
            ),
        ) as manager:
            state = manager.run()
            self.assertEqual(state.unit_status, ops.ActiveStatus())
            self.assertEqual(len(state.deferred), 0)
            self.assertListEqual(
                self.ctx.unit_status_history[1:],
                [
                    ops.MaintenanceStatus(
                        f"Adding domain `{ldap_remote_app_name}` to SSSD configuration"
                    ),
                    ops.MaintenanceStatus("Enabling SSSD"),
                ],
            )
            mock_sssd.add_ldap_domain.assert_called_once_with(
                ldap_remote_app_name,
                mock_client_side_provider_data,
            )
            mock_sssd.update_ldap_domain.assert_not_called()
            mock_sssd.enable.assert_called_once()
            mock_sssd.restart.assert_not_called()

        # Test `ldap_ready` hook when a second domain is added.
        self.ctx.unit_status_history.clear()
        self.ctx.emitted_events.clear()
        mock_sssd.add_ldap_domain.reset_mock()
        mock_sssd.enable.reset_mock()
        mock_sssd.domains.return_value = [ldap_remote_app_name]
        mock_sssd.active.return_value = True

        with self.ctx(
            self.ctx.on.relation_changed(ldap_relation),
            testing.State(
                relations={ldap_relation, receive_ca_cert_relation}, secrets={ldap_secret}
            ),
        ) as manager:
            state = manager.run()
            self.assertEqual(state.unit_status, ops.ActiveStatus())
            self.assertEqual(len(state.deferred), 0)
            self.assertListEqual(
                self.ctx.unit_status_history[1:],
                [
                    ops.MaintenanceStatus(
                        f"Updating domain `{ldap_remote_app_name}` in SSSD configuration"
                    ),
                    ops.MaintenanceStatus("Restarting SSSD"),
                ],
            )
            mock_sssd.add_ldap_domain.assert_not_called()
            mock_sssd.update_ldap_domain.assert_called_once_with(
                ldap_remote_app_name,
                mock_client_side_provider_data,
            )
            mock_sssd.enable.assert_not_called()
            mock_sssd.restart.assert_called_once()

    @reset_mock_sssd_module
    def test_ldap_unavailable(self) -> None:
        """Test the `_on_ldap_unavailable` hook."""
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
        mock_sssd.domains.return_value = ["polaris"]
        mock_sssd.active.return_value = True

        with self.ctx(
            self.ctx.on.relation_broken(ldap_relation),
            testing.State(relations={ldap_relation, ldap_relation_2}),
        ) as manager:
            state = manager.run()
            self.assertEqual(state.unit_status, ops.ActiveStatus())
            self.assertListEqual(
                self.ctx.unit_status_history[1:], [ops.MaintenanceStatus("Restarting SSSD")]
            )
            mock_sssd.remove_ldap_domain.assert_called_once_with("glauth")
            mock_sssd.disable.assert_not_called()
            mock_sssd.restart.assert_called_once()

        # Test `ldap_unavailable` hook when there's no more domains in `sssd.conf`
        self.ctx.unit_status_history.clear()
        mock_sssd.remove_ldap_domain.reset_mock()
        mock_sssd.restart.reset_mock()
        mock_sssd.domains.return_value = []
        mock_sssd.active.return_value = False

        with self.ctx(
            self.ctx.on.relation_broken(ldap_relation),
            testing.State(relations={ldap_relation}),
        ) as manager:
            state = manager.run()
            self.assertEqual(
                state.unit_status,
                ops.WaitingStatus(f"Waiting for integrations: [`{LDAP_INTEGRATION_NAME}`]"),
            )
            self.assertListEqual(
                self.ctx.unit_status_history[1:], [ops.MaintenanceStatus("Disabling SSSD")]
            )
            mock_sssd.remove_ldap_domain.assert_called_once_with("glauth")
            mock_sssd.disable.assert_called_once()
            mock_sssd.restart.assert_not_called()

    @reset_mock_sssd_module
    def test_certificate_available(self) -> None:
        """Test the `_on_certificate_available` hook."""
        ldap_relation = testing.Relation(endpoint=LDAP_INTEGRATION_NAME, interface="ldap", id=23)

        cert_remote_unit_data = {
            "certificate": (cert := "super-secret-cert"),
            "ca": (ca := "super-secret-ca-cert"),
            "chain": json.dumps([cert, ca]),
        }
        receive_ca_cert_relation = testing.Relation(
            endpoint=CERTIFICATES_TRANSFER_INTEGRATION_NAME,
            interface="certificate_transfer",
            id=24,
            remote_units_data={0: cert_remote_unit_data},
        )

        # Test `certificate_available` hook reaches target state with no errors.
        with self.ctx(
            self.ctx.on.relation_changed(receive_ca_cert_relation),
            testing.State(relations={ldap_relation, receive_ca_cert_relation}),
        ) as manager:
            state = manager.run()
            self.assertEqual(state.unit_status, ops.ActiveStatus())
            mock_sssd.add_tls_certs.assert_called_once_with(
                24, ["super-secret-cert", "super-secret-ca-cert"]
            )
            self.assertListEqual(
                self.ctx.unit_status_history[1:],
                [ops.MaintenanceStatus("Adding new TLS certificates")],
            )

        # Test when `certificate_available` hook fails to add new certificates.
        self.ctx.unit_status_history.clear()
        mock_sssd.add_tls_certs.side_effect = sssd.SSSDOpsError("failed to add tls certs!!")

        with self.ctx(
            self.ctx.on.relation_changed(receive_ca_cert_relation),
            testing.State(relations={ldap_relation, receive_ca_cert_relation}),
        ) as manager:
            state = manager.run()
            self.assertEqual(
                state.unit_status,
                ops.BlockedStatus(
                    "Failed to add new TLS certificates. See `juju debug-log` for details"
                ),
            )
            self.assertListEqual(
                self.ctx.unit_status_history[1:],
                [ops.MaintenanceStatus("Adding new TLS certificates")],
            )

    @reset_mock_sssd_module
    def test_certificate_removed(self) -> None:
        """Test the `_on_certificate_removed` hook."""
        ldap_relation = testing.Relation(endpoint=LDAP_INTEGRATION_NAME, interface="ldap", id=23)

        receive_ca_cert_relation = testing.Relation(
            endpoint=CERTIFICATES_TRANSFER_INTEGRATION_NAME,
            interface="certificate_transfer",
            id=24,
        )

        # Test `certificate_unavailable` hook reaches target state with no errors.
        with self.ctx(
            self.ctx.on.relation_broken(receive_ca_cert_relation),
            testing.State(relations={ldap_relation, receive_ca_cert_relation}),
        ) as manager:
            state = manager.run()
            self.assertEqual(state.unit_status, ops.ActiveStatus())
            mock_sssd.remove_tls_certs.assert_called_once_with(24)
            self.assertListEqual(
                self.ctx.unit_status_history[1:],
                [ops.MaintenanceStatus("Removing stale TLS certificates")],
            )

        # Test when `certificate_unavailable` hook fails to remove stale certificates.
        self.ctx.unit_status_history.clear()
        mock_sssd.remove_tls_certs.side_effect = sssd.SSSDOpsError("failed to remove tls certs!!")

        with self.ctx(
            self.ctx.on.relation_broken(receive_ca_cert_relation),
            testing.State(relations={ldap_relation, receive_ca_cert_relation}),
        ) as manager:
            state = manager.run()
            self.assertEqual(
                state.unit_status,
                ops.BlockedStatus(
                    "Failed to remove stale TLS certificates. See `juju debug-log` for details"
                ),
            )
            self.assertListEqual(
                self.ctx.unit_status_history[1:],
                [ops.MaintenanceStatus("Removing stale TLS certificates")],
            )

    @reset_mock_sssd_module
    def test_refresh(self) -> None:
        """Test `refresh` decorator."""
        ldap_relation = testing.Relation(endpoint=LDAP_INTEGRATION_NAME, interface="ldap", id=23)

        # Test that `refresh` will say sssd is not running if service is not active.
        mock_sssd.active.return_value = False
        mock_sssd.version.return_value = "2.9.4-1.1ubuntu6.2"

        with self.ctx(self.ctx.on.install(), testing.State(relations={ldap_relation})) as manager:
            state = manager.run()
            self.assertEqual(state.unit_status, ops.BlockedStatus("SSSD not running"))
