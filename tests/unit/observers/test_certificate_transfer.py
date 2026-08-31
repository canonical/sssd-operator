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

"""Unit tests for the ``CertificateTransferObserver`` integration observer."""

import json
from unittest.mock import Mock

import ops
from ops import testing

import sssd
from charm import SSSDCharm
from constants import CERTIFICATES_TRANSFER_INTEGRATION_NAME, LDAP_INTEGRATION_NAME


class TestCertificateTransferObserver:
    """Test the ``certificate_transfer`` integration event observer."""

    def test_certificates_available(
        self, mock_charm: testing.Context[SSSDCharm], mock_sssd: Mock
    ) -> None:
        """Test the ``_on_certificates_available`` event handler."""
        ldap_relation = testing.Relation(endpoint=LDAP_INTEGRATION_NAME, interface="ldap", id=23)

        # v1 ``certificate_transfer`` stores certificates in the provider's *application*
        # databag as a JSON-encoded list under the ``certificates`` key, with ``version: 1``
        # in the requirer's local app databag. See ``charmlibs/interfaces/certificate_transfer``.
        receive_ca_cert_relation = testing.Relation(
            endpoint=CERTIFICATES_TRANSFER_INTEGRATION_NAME,
            interface="certificate_transfer",
            id=24,
            local_app_data={"version": "1"},
            remote_app_data={
                "certificates": json.dumps(["super-secret-cert", "super-secret-ca-cert"])
            },
        )

        # Test ``certificates_available`` hook reaches target state with no errors.
        mock_sssd.service.is_active.return_value = True
        with mock_charm(
            mock_charm.on.relation_changed(receive_ca_cert_relation),
            testing.State(relations={ldap_relation, receive_ca_cert_relation}),
        ) as manager:
            state = manager.run()
            assert state.unit_status == ops.ActiveStatus()
            # ``event.certificates`` is a ``set[str]``; assert via set comparison for determinism.
            mock_sssd.add_tls_certs.assert_called_once()
            call_args = mock_sssd.add_tls_certs.call_args
            assert call_args[0][0] == 24
            assert set(call_args[0][1]) == {"super-secret-cert", "super-secret-ca-cert"}
            assert mock_charm.unit_status_history[1:] == [
                ops.MaintenanceStatus("Adding new TLS certificates")
            ]

        # Test when ``certificates_available`` hook fails to add new certificates.
        mock_charm.unit_status_history.clear()
        mock_sssd.add_tls_certs.side_effect = sssd.SSSDOpsError("failed to add tls certs!!")

        with mock_charm(
            mock_charm.on.relation_changed(receive_ca_cert_relation),
            testing.State(relations={ldap_relation, receive_ca_cert_relation}),
        ) as manager:
            state = manager.run()
            assert state.unit_status == ops.BlockedStatus(
                "Failed to add new TLS certificates. See `juju debug-log` for details"
            )
            assert mock_charm.unit_status_history[1:] == [
                ops.MaintenanceStatus("Adding new TLS certificates")
            ]

    def test_certificates_removed(
        self, mock_charm: testing.Context[SSSDCharm], mock_sssd: Mock
    ) -> None:
        """Test the ``_on_certificates_removed`` event handler."""
        ldap_relation = testing.Relation(endpoint=LDAP_INTEGRATION_NAME, interface="ldap", id=23)

        receive_ca_cert_relation = testing.Relation(
            endpoint=CERTIFICATES_TRANSFER_INTEGRATION_NAME,
            interface="certificate_transfer",
            id=24,
            local_app_data={"version": "1"},
        )

        # Test ``certificates_removed`` hook reaches target state with no errors.
        mock_sssd.service.is_active.return_value = True
        with mock_charm(
            mock_charm.on.relation_broken(receive_ca_cert_relation),
            testing.State(relations={ldap_relation, receive_ca_cert_relation}),
        ) as manager:
            state = manager.run()
            assert state.unit_status == ops.ActiveStatus()
            mock_sssd.remove_tls_certs.assert_called_once_with(24)
            assert mock_charm.unit_status_history[1:] == [
                ops.MaintenanceStatus("Removing stale TLS certificates")
            ]

        # Test when ``certificates_removed`` hook fails to remove stale certificates.
        mock_charm.unit_status_history.clear()
        mock_sssd.remove_tls_certs.side_effect = sssd.SSSDOpsError("failed to remove tls certs!!")

        with mock_charm(
            mock_charm.on.relation_broken(receive_ca_cert_relation),
            testing.State(relations={ldap_relation, receive_ca_cert_relation}),
        ) as manager:
            state = manager.run()
            assert state.unit_status == ops.BlockedStatus(
                "Failed to remove stale TLS certificates. See `juju debug-log` for details"
            )
            assert mock_charm.unit_status_history[1:] == [
                ops.MaintenanceStatus("Removing stale TLS certificates")
            ]
