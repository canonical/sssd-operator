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

"""Charmed operator for SSSD, the System Security Services Daemon."""

import logging
from typing import cast

import ops
from charms.certificate_transfer_interface.v0.certificate_transfer import (
    CertificateAvailableEvent,
    CertificateRemovedEvent,
    CertificateTransferRequires,
)
from charms.glauth_k8s.v0.ldap import (
    LdapProviderData,
    LdapReadyEvent,
    LdapRequirer,
    LdapUnavailableEvent,
)

import sssd
from constants import CERTIFICATES_TRANSFER_INTEGRATION_NAME, LDAP_INTEGRATION_NAME
from utils import StopCharm, certificates_transfer_integration_exists, refresh

logger = logging.getLogger(__name__)


class SSSDCharm(ops.CharmBase):
    """Charmed operator for SSSD, the System Security Services Daemon."""

    def __init__(self, *args) -> None:
        super().__init__(*args)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.stop, self._on_stop)

        self._ldap = LdapRequirer(self, LDAP_INTEGRATION_NAME)
        self.framework.observe(
            self._ldap.on.ldap_ready,
            self._on_ldap_ready,
        )
        self.framework.observe(
            self._ldap.on.ldap_unavailable,
            self._on_ldap_unavailable,
        )

        self._certificate_transfer = CertificateTransferRequires(
            self, CERTIFICATES_TRANSFER_INTEGRATION_NAME
        )
        self.framework.observe(
            self._certificate_transfer.on.certificate_available,
            self._on_certificate_available,
        )
        self.framework.observe(
            self._certificate_transfer.on.certificate_removed,
            self._on_certificate_removed,
        )

    @refresh
    def _on_install(self, event: ops.InstallEvent) -> None:
        """Handle when sssd charm is installed on unit."""
        self.unit.status = ops.MaintenanceStatus("Installing SSSD...")
        try:
            sssd.install()
            self.unit.set_workload_version(sssd.version())
        except sssd.SSSDOpsError as e:
            logger.error(e.message)
            event.defer()
            raise StopCharm(
                ops.BlockedStatus("Failed to install SSSD. See `juju debug-log` for details")
            )

    def _on_stop(self, _: ops.StopEvent) -> None:
        """Handle when sssd unit is going to be torn down by Juju."""
        self.unit.status = ops.MaintenanceStatus("Disabling SSSD...")
        sssd.disable()
        self.unit.status = ops.MaintenanceStatus("Removing SSSD...")
        sssd.remove()
        self.unit.status = ops.MaintenanceStatus("SSSD removed")

    @refresh
    def _on_ldap_ready(self, event: LdapReadyEvent) -> None:
        """Handle ldap-ready event."""
        name = event.relation.app.name
        # `data` cannot be `None` since `LdapReadyEvent` will not be emitted by the ldap charm
        # library if the remote application data bag is empty. However, `pyright` complains here
        # anyway so just signal to type checker that return value is `LdapProviderData`.
        data = cast(
            LdapProviderData, self._ldap.consume_ldap_relation_data(relation=event.relation)
        )
        domains = sssd.domains()

        if data.starttls and not certificates_transfer_integration_exists(self):
            logger.warning(
                (
                    "ldap domain `%s` has starttls enabled, but the %s integration is missing. "
                    "cannot add domain to sssd configuration until the domain's tls certificates "
                    "are provided. deferring until tls certificates are provided"
                ),
                name,
                CERTIFICATES_TRANSFER_INTEGRATION_NAME,
            )
            event.defer()
            raise StopCharm(
                ops.WaitingStatus(
                    f"Waiting for integrations: [`{CERTIFICATES_TRANSFER_INTEGRATION_NAME}`]"
                )
            )

        if name not in domains:
            self.unit.status = ops.MaintenanceStatus(
                f"Adding domain `{name}` to SSSD configuration..."
            )
            sssd.add_ldap_domain(name, data)
        else:
            self.unit.status = ops.MaintenanceStatus(
                f"Updating domain `{name}` in SSSD configuration..."
            )
            sssd.update_ldap_domain(name, data)

        if len(domains) == 0:
            logger.info("first domain added to sssd configuration. enabling sssd service")
            self.unit.status = ops.MaintenanceStatus("Enabling SSSD...")
            sssd.enable()
        else:
            logger.info("sssd configuration has been updated. restarting sssd service")
            self.unit.status = ops.MaintenanceStatus("Restarting SSSD...")
            sssd.restart()

    @refresh
    def _on_ldap_unavailable(self, event: LdapUnavailableEvent) -> None:
        """Handle server-unavailable event."""
        domain = event.relation.app.name
        sssd.remove_ldap_domain(domain)
        if domains := sssd.domains():
            logger.info("restarting sssd service with configured domains %s", domains)
            self.unit.status = ops.MaintenanceStatus("Restarting SSSD...")
            sssd.restart()
        else:
            logger.info("no domains exist in sssd configuration. disabling sssd service")
            self.unit.status = ops.MaintenanceStatus("Disabling SSSD...")
            sssd.disable()

    @refresh
    def _on_certificate_available(self, event: CertificateAvailableEvent):
        """Handle `CertificateAvailableEvent`."""
        self.unit.status = ops.MaintenanceStatus("Adding new TLS certificates...")
        try:
            sssd.add_tls_certs(event.relation_id, event.chain)
        except sssd.SSSDOpsError as e:
            logger.error(e.message)
            raise StopCharm(
                ops.BlockedStatus(
                    "Failed to add new TLS certificates. See `juju debug-log` for details"
                )
            )

    @refresh
    def _on_certificate_removed(self, event: CertificateRemovedEvent) -> None:
        """Handle certificate-unavailable event."""
        self.unit.status = ops.MaintenanceStatus("Removing stale TLS certificates...")
        try:
            sssd.remove_tls_certs(event.relation_id)
        except sssd.SSSDOpsError as e:
            logger.error(e.message)
            raise StopCharm(
                ops.BlockedStatus(
                    "Failed to remove stale TLS certificates. See `juju debug-log` for details"
                )
            )


if __name__ == "__main__":  # pragma: nocover
    ops.main(SSSDCharm)
