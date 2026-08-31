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

"""Observe ``ldap`` integration events for the SSSD charm."""

import logging
from typing import TYPE_CHECKING, cast

import ops
from charmed_hpc_libs.ops import Observer, StopCharm, integration_exists, refresh
from charmlibs.interfaces.ldap import (
    LdapProviderData,
    LdapReadyEvent,
    LdapRequirer,
    LdapUnavailableEvent,
)

from constants import CERTIFICATES_TRANSFER_INTEGRATION_NAME, LDAP_INTEGRATION_NAME
from state import check_sssd

if TYPE_CHECKING:
    from charm import SSSDCharm

_logger = logging.getLogger(__name__)
refresh = refresh(hook=check_sssd)
certificates_transfer_exists = integration_exists(CERTIFICATES_TRANSFER_INTEGRATION_NAME)


class LdapObserver(Observer):
    """Observe ``ldap`` integration events for the SSSD charm."""

    def __init__(self, charm: "SSSDCharm") -> None:
        super().__init__(charm)

        self.ldap = LdapRequirer(self.charm, LDAP_INTEGRATION_NAME)
        self.charm.framework.observe(self.ldap.on.ldap_ready, self._on_ldap_ready)
        self.charm.framework.observe(self.ldap.on.ldap_unavailable, self._on_ldap_unavailable)

    @refresh
    def _on_ldap_ready(self, event: LdapReadyEvent) -> None:
        """Handle when the ``ldap`` integration is ready."""
        # `data` cannot be `None` since `LdapReadyEvent` will not be emitted by the ldap charm
        # library if the remote application data bag is empty or if required data is missing.
        #
        # However, `pyright` complains anyway so just signal to the type checker that the return
        # value will always be `LdapProviderData`.
        data = cast(
            LdapProviderData, self.ldap.consume_ldap_relation_data(relation=event.relation)
        )
        name = event.relation.app.name
        domains = self.charm.sssd.config.domains()

        if data.starttls and not certificates_transfer_exists(self.charm).ok:
            _logger.warning(
                (
                    "ldap domain `%s` has starttls enabled, but the %s integration is missing. "
                    + "cannot add domain to sssd configuration until the domain's tls "
                    + "certificates are provided. deferring until tls certificates are provided"
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
            self.charm.unit.status = ops.MaintenanceStatus(
                f"Adding domain `{name}` to SSSD configuration"
            )
            self.charm.sssd.config.add_ldap_domain(name, data)
        else:
            self.charm.unit.status = ops.MaintenanceStatus(
                f"Updating domain `{name}` in SSSD configuration"
            )
            self.charm.sssd.config.update_ldap_domain(name, data)

        if len(domains) == 0:
            _logger.info("first domain added to sssd configuration. enabling sssd service")
            self.charm.unit.status = ops.MaintenanceStatus("Enabling SSSD")
            self.charm.sssd.service.enable()
            self.charm.unit.status = ops.MaintenanceStatus("Starting SSSD")
            self.charm.sssd.service.restart()
        else:
            _logger.info("sssd configuration has been updated. restarting sssd service")
            self.charm.unit.status = ops.MaintenanceStatus("Restarting SSSD")
            self.charm.sssd.service.restart()

    @refresh
    def _on_ldap_unavailable(self, event: LdapUnavailableEvent) -> None:
        """Handle when the ``ldap`` integration is unavailable."""
        domain = event.relation.app.name
        self.charm.sssd.config.remove_ldap_domain(domain)
        if domains := self.charm.sssd.config.domains():
            _logger.info("restarting sssd service with configured domains %s", domains)
            self.charm.unit.status = ops.MaintenanceStatus("Restarting SSSD")
            self.charm.sssd.service.restart()
        else:
            _logger.info("no domains exist in sssd configuration. disabling sssd service")
            self.charm.unit.status = ops.MaintenanceStatus("Disabling SSSD")
            self.charm.sssd.service.disable()
