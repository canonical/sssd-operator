# Copyright 2023 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Library for the ldap-client relation.

This library contains the Provides and Requires classes for handling the ldap-client interface.


### Provider Charm

### Requirer Charm


"""

import logging
import pathlib
import socket
import zipfile

from ops.charm import (
    CharmBase,
    CharmEvents,
    RelationBrokenEvent,
    RelationChangedEvent,
    RelationJoinedEvent,
)
from ops.framework import EventBase, EventSource, Handle, Object
from ops.model import ActiveStatus, MaintenanceStatus, ModelError

logger = logging.getLogger(__name__)


class CertificateAvailableEvent(EventBase):
    """Charm Event triggered when a CA certificate is available."""

    def __init__(
        self,
        handle: Handle,
        ca_cert: str,
    ):
        super().__init__(handle)
        self.ca_cert = ca_cert

    def snapshot(self) -> dict:
        """Return snapshot."""
        return {
            "ca_cert": self.ca_cert,
        }

    def restore(self, snapshot: dict):
        """Restore snapshot."""
        self.ca_cert = snapshot["ca_cert"]


class CertificateUnavailableEvent(EventBase):
    """Charm Event triggered when a CA certificate is unavailable."""


class ConfigDataAvailableEvent(EventBase):
    """Charm Event triggered when config data is available."""

    def __init__(
        self,
        handle: Handle,
        basedn: str,
        ldap_uri: str,
        ldbd_content: str,
        lp_content: str,
    ):
        super().__init__(handle)
        self.basedn = basedn
        self.ldap_uri = ldap_uri
        self.ldbd_content = ldbd_content
        self.lp_content = lp_content

    def snapshot(self) -> dict:
        """Return snapshot."""
        return {
            "basedn": self.basedn,
            "ldap_uri": self.ldap_uri,
            "ldbd_content": self.ldbd_content,
            "lp_content": self.lp_content,
        }

    def restore(self, snapshot: dict):
        """Restore snapshot."""
        self.basedn = snapshot["basedn"]
        self.ldap_uri = snapshot["ldap_uri"]
        self.ldbd_content = snapshot["ldbd_content"]
        self.lp_content = snapshot["lp_content"]


class ConfigDataUnavailableEvent(EventBase):
    """Charm Event triggered when config data is unavailable."""

    def __init__(
        self,
        handle: Handle,
        api_port: int,
    ):
        super().__init__(handle)
        self.api_port = api_port

    def snapshot(self) -> dict:
        """Return snapshot."""
        return {
            "api_port": self.api_port,
        }

    def restore(self, snapshot: dict):
        """Restore snapshot."""
        self.api_port = snapshot["api_port"]


class ServerUnavailableEvent(EventBase):
    """Charm Event triggered When the LDAP server is unavailable."""


class LdapReadyEvent(EventBase):
    """Charm Event triggered when LDAP is ready to start."""


class LdapClientProviderCharmEvents(CharmEvents):
    """Events the LDAP Client requirer can leverage."""

    config_data_unavailable = EventSource(ConfigDataUnavailableEvent)
    ldap_ready = EventSource(LdapReadyEvent)
    server_unavailable = EventSource(ServerUnavailableEvent)


class LdapClientRequirerCharmEvents(CharmEvents):
    """Events the LDAP Client requirer can leverage."""

    certificate_available = EventSource(CertificateAvailableEvent)
    certificate_unavailable = EventSource(CertificateUnavailableEvent)
    config_data_available = EventSource(ConfigDataAvailableEvent)
    config_data_unavailable = EventSource(ConfigDataUnavailableEvent)
    server_unavailable = EventSource(ServerUnavailableEvent)
    ldap_ready = EventSource(LdapReadyEvent)


class LdapClientProvides(Object):
    """Provides-side of the ldapclient integration."""

    on = LdapClientProviderCharmEvents()

    def __init__(self, charm: CharmBase, integration_name: str) -> None:
        super().__init__(charm, integration_name)
        self.framework.observe(
            charm.on[integration_name].relation_broken,
            self._on_relation_broken,
        )
        self.framework.observe(
            charm.on[integration_name].relation_joined,
            self._on_relation_joined,
        )
        self.charm = charm
        self.integration_name = integration_name

    def _on_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Handle relation-broken event.

        When the ldapclient relation is broken and emits:
        - Server unavailable event: When the ldap server can't be reached.
        """
        # Remove Obsolete Secrets
        ca_cert_secret = self.model.get_secret(label="ca-cert")
        ldbd_secret = self.model.get_secret(label="ldap-default-bind-dn")
        lp_secret = self.model.get_secret(label="ldap-password")
        ca_cert_secret.remove_all_revisions()
        ldbd_secret.remove_all_revisions()
        lp_secret.remove_all_revisions()
        self.on.server_unavailable.emit()

    def _on_relation_joined(self, event: RelationJoinedEvent) -> None:
        """Event emitted when the relation is joined.

        Looks at the relation data and config values and emits:
        - config unavailable event: If the config resource is not supplied.
        - ldap ready event: When the necessary ldap components are available.
        """
        self.charm.unit.status = MaintenanceStatus("reconfiguring ldap")

        # Check model for GLAuth config resource
        try:
            resource_path = self.model.resources.fetch("config")
        except ModelError:
            logger.debug("No config resource supplied")
            self.on.config_data_unavailable.emit(api_port=self.model.config["api-port"])
            resource_path = None

        # Set config and get LDAP URI
        ldap_uri = self.set_config(self.model.config["tls"], config=resource_path)

        # Get App Peer Secrets
        ldap_relation = self.model.get_relation(self.charm.app.name)
        ca_cert = ldap_relation.data[self.charm.app]["ca-cert"]
        default_bind_dn = ldap_relation.data[self.charm.app]["ldap-default-bind-dn"]
        ldap_password = ldap_relation.data[self.charm.app]["ldap-password"]
        cc_secret = self.model.get_secret(id=ca_cert)
        ldbd_secret = self.model.get_secret(id=default_bind_dn)
        lp_secret = self.model.get_secret(id=ldap_password)

        # Signals ldap is ready to be started
        self.on.ldap_ready.emit()

        # Create Secrets
        cc_secret.grant(event.relation)
        ldbd_secret.grant(event.relation)
        lp_secret.grant(event.relation)
        event.relation.data[self.charm.app]["ca-cert"] = cc_secret.id
        event.relation.data[self.charm.app]["ldap-default-bind-dn"] = ldbd_secret.id
        event.relation.data[self.charm.app]["ldap-password"] = lp_secret.id

        # Configuration data update
        ldap_relation = self.model.get_relation("ldap-client")
        ldap_relation.data[self.charm.app].update(
            {
                "basedn": self.model.config["ldap-search-base"],
                "ldap-uri": ldap_uri,
            }
        )
        self.charm.unit.status = ActiveStatus()

    def set_config(self, tls: bool, config: pathlib.Path) -> str:
        """Set GLAuth config resource. Create default if none found.

        Args:
            tls: TLS check.
            config: Resource config Path object.


        Returns:
            str: LDAP URI.
        """
        if config:
            with zipfile.ZipFile(config, "r") as zip:
                zip.extractall("/var/snap/glauth/common/etc/glauth/glauth.d/")
        if tls:
            ldap_uri = f"ldaps://{socket.gethostname()}:636"
        else:
            ldap_uri = f"ldap://{socket.gethostname()}:363"
        return ldap_uri


class LdapClientRequires(Object):
    """Requires-side of the ldapclient integration."""

    on = LdapClientRequirerCharmEvents()

    def __init__(self, charm: CharmBase, integration_name: str) -> None:
        super().__init__(charm, integration_name)
        self.framework.observe(
            charm.on[integration_name].relation_changed,
            self._on_relation_changed,
        )
        self.framework.observe(
            charm.on[integration_name].relation_broken,
            self._on_relation_broken,
        )
        self.charm = charm
        self.integration_name = integration_name

    def _on_relation_broken(self, event: RelationBrokenEvent):
        """Handle relation-broken event.

        When the ldapclient relation is broken and emits:
        - Server unavailable event: When the ldap server can't be reached.
        """
        self.on.server_unavailable.emit()

    def _on_relation_changed(self, event: RelationChangedEvent):
        """Handle relation-changed event.

        Looks at the relation data and either emits:
        - Certificate available event: When a CA certificate is available.
        - Certificate unavailable event: When a CA certificate is unavailable.
        - Configuration data available event: When configuration data is available.
        - Configuration data unavailable event: When configuration data is unavailable.
        - Ldap ready event: When cert and config are available.
        """
        # SSSD Observer retrieves secrets
        ca_cert = event.relation.data[event.app]["ca-cert"]
        default_bind_dn = event.relation.data[event.app]["ldap-default-bind-dn"]
        ldap_password = event.relation.data[event.app]["ldap-password"]
        cc_secret = self.model.get_secret(id=ca_cert)
        ldbd_secret = self.model.get_secret(id=default_bind_dn)
        lp_secret = self.model.get_secret(id=ldap_password)
        cc_content = cc_secret.get_content()
        ldbd_content = ldbd_secret.get_content()
        lp_content = lp_secret.get_content()
        if None not in [cc_content["ca-cert"]]:
            self.on.certificate_available.emit(ca_cert=cc_content["ca-cert"])
        # SSSD Configuration relation data
        auth_relation = self.model.get_relation("ldap-client")
        basedn = auth_relation.data[event.app].get("basedn")
        ldap_uri = auth_relation.data[event.app].get("ldap-uri")
        if None not in [
            ldbd_content["ldap-default-bind-dn"],
            lp_content["ldap-password"],
            basedn,
            ldap_uri,
        ]:
            self.on.config_data_available.emit(
                basedn=basedn,
                ldap_uri=ldap_uri,
                ldbd_content=ldbd_content["ldap-default-bind-dn"],
                lp_content=lp_content["ldap-password"],
            )
            self.on.ldap_ready.emit()
        else:
            logger.error("sssd-ldap relation-changed data not found: ca-cert and sssd-conf.")
