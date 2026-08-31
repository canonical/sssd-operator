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

"""Observe ``certificate_transfer`` integration events for the SSSD charm."""

import logging
from typing import TYPE_CHECKING

import ops
from charmed_hpc_libs.ops import Observer, StopCharm, refresh
from charms.certificate_transfer_interface.v0.certificate_transfer import (
    CertificateAvailableEvent,
    CertificateRemovedEvent,
    CertificateTransferRequires,
)

from constants import CERTIFICATES_TRANSFER_INTEGRATION_NAME
from sssd import SSSDOpsError
from state import check_sssd

if TYPE_CHECKING:
    from charm import SSSDCharm

_logger = logging.getLogger(__name__)
refresh = refresh(hook=check_sssd)


class CertificateTransferObserver(Observer):
    """Observe ``certificate_transfer`` integration events for the SSSD charm."""

    def __init__(self, charm: "SSSDCharm") -> None:
        super().__init__(charm)
        self.certificate_transfer = CertificateTransferRequires(
            self.charm, CERTIFICATES_TRANSFER_INTEGRATION_NAME
        )
        self.charm.framework.observe(
            self.certificate_transfer.on.certificate_available,
            self._on_certificate_available,
        )
        self.charm.framework.observe(
            self.certificate_transfer.on.certificate_removed,
            self._on_certificate_removed,
        )

    @refresh
    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Handle when new TLS certificates are available from a provider."""
        self.charm.unit.status = ops.MaintenanceStatus("Adding new TLS certificates")
        try:
            self.charm.sssd.add_tls_certs(event.relation_id, event.chain)
        except SSSDOpsError as e:
            _logger.exception(e.message)
            raise StopCharm(
                ops.BlockedStatus(
                    "Failed to add new TLS certificates. See `juju debug-log` for details"
                )
            )

    @refresh
    def _on_certificate_removed(self, event: CertificateRemovedEvent) -> None:
        """Handle when TLS certificates are removed by a provider."""
        self.charm.unit.status = ops.MaintenanceStatus("Removing stale TLS certificates")
        try:
            self.charm.sssd.remove_tls_certs(event.relation_id)
        except SSSDOpsError as e:
            _logger.exception(e.message)
            raise StopCharm(
                ops.BlockedStatus(
                    "Failed to remove stale TLS certificates. See `juju debug-log` for details"
                )
            )
