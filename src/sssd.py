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

"""Manage the internal SSSD daemon on Juju machines."""

import configparser
import logging
import os
import shutil
import subprocess
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from functools import cached_property
from pathlib import Path

from charmed_hpc_libs.errors import Error
from charmed_hpc_libs.ops import AptLifecycleManager, SystemctlServiceManager
from charmlibs.interfaces.ldap import LdapProviderData

_logger = logging.getLogger(__name__)
_SSSD_CONFIG_FILE = "/etc/sssd/sssd.conf"


class SSSDOpsError(Error):
    """Exception raised when a SSSD operation has failed."""


class SSSDConfigManager:
    """Manage the ``sssd.conf`` service configuration file."""

    def init(self) -> None:
        """Initialize the ``sssd.conf`` service configuration file."""
        _logger.info("seeding initial sssd configuration file at %s", _SSSD_CONFIG_FILE)
        with self.edit() as config:
            config["sssd"] = {"config_file_version": "2"}

    def read(self) -> configparser.ConfigParser:
        """Read the contents of the ``sssd.conf`` service configuration file."""
        config = configparser.ConfigParser()
        config.read(_SSSD_CONFIG_FILE)
        return config

    @contextmanager
    def edit(self) -> Iterator[configparser.ConfigParser]:
        """Edit the ``sssd.conf`` service configuration file."""
        config_file = Path(_SSSD_CONFIG_FILE)
        # Ensure `/etc/sssd` exists. Typically, this dir is created by the `sssd` deb package,
        # but this method should be impervious to if another process destroys `/etc/sssd`.
        config_file.parent.mkdir(mode=0o711, parents=True, exist_ok=True)
        config_file.touch()
        config_file.chmod(0o600)
        os.chown(config_file, 0, 0)

        config = self.read()
        yield config
        with config_file.open(mode="w") as fout:
            config.write(fout)

    def delete(self) -> None:
        """Delete the ``sssd.conf`` configuration file."""
        _logger.info("removing sssd configuration file %s", _SSSD_CONFIG_FILE)
        Path(_SSSD_CONFIG_FILE).unlink(missing_ok=True)

    def domains(self) -> list[str]:
        """Get list of configured sssd domains."""
        config = self.read()
        domains_ = config["sssd"].get("domains", "")
        return domains_.split(",") if domains_ else []

    def add_ldap_domain(self, name: str, data: LdapProviderData) -> None:
        """Add a new LDAP domain to the ``sssd`` service configuration.

        Args:
            name: Name of LDAP domain.
            data: Domain configuration data received from LDAP provider.
        """
        _logger.info(
            "adding ldap domain `%s` to sssd configuration file %s", name, _SSSD_CONFIG_FILE
        )

        domain_config = {
            "id_provider": "ldap",
            "auth_provider": "ldap",
            "ldap_uri": ",".join(data.urls),
            "ldap_search_base": data.base_dn,
            "ldap_default_bind_dn": data.bind_dn,
            "ldap_default_authtok_type": "password",
            "ldap_default_authtok": data.bind_password,
            "ldap_use_tokengroups": "False",
            "ldap_group_member": "member",
            "ldap_schema": "rfc2307bis",
            "ldap_id_use_start_tls": "True" if data.starttls else "False",
            "cache_credentials": "True",
        }
        with self.edit() as config:
            try:
                config["sssd"]["domains"] += f",{name}"
            except KeyError:
                config["sssd"]["domains"] = name

            config[f"domain/{name}"] = domain_config

    def update_ldap_domain(self, name: str, data: LdapProviderData) -> None:
        """Update an LDAP domain in the ``sssd`` service configuration.

        Args:
            name: Name of LDAP domain to update.
            data: Updated domain configuration data received from LDAP provider.

        Notes:
            This method will add a new LDAP domain to the ``sssd`` service configuration
            if it does not exist within the current service configuration.
        """
        if name not in self.domains():
            self.add_ldap_domain(name, data)
            return

        _logger.info(
            "updating ldap domain `%s` in sssd configuration file %s", name, _SSSD_CONFIG_FILE
        )
        diff = {
            "ldap_uri": ",".join(data.urls),
            "ldap_search_base": data.base_dn,
            "ldap_default_bind_dn": data.bind_dn,
            "ldap_default_authtok": data.bind_password,
            "ldap_id_use_start_tls": "True" if data.starttls else "False",
        }
        domain_config_name = f"domain/{name}"
        with self.edit() as config:
            config[domain_config_name] = dict(config[domain_config_name]) | diff

    def remove_ldap_domain(self, name: str) -> None:
        """Remove an LDAP domain from the ``sssd`` service configuration.

        Args:
            name: Name of LDAP domain to remove.
        """
        _logger.info(
            "removing ldap domain `%s` from sssd configuration file %s", name, _SSSD_CONFIG_FILE
        )
        with self.edit() as config:
            domains_ = config["sssd"]["domains"].split(",")
            domains_.remove(name)
            if domains_:
                config["sssd"]["domains"] = ",".join(domains_)
            else:
                del config["sssd"]["domains"]

            del config[f"domain/{name}"]


class SSSDManager(AptLifecycleManager):
    """Manage the SSSD installation of a machine."""

    def __init__(self) -> None:
        super().__init__("sssd", additional_packages=["sssd-common", "sssd-ldap"])

    @cached_property
    def config(self) -> SSSDConfigManager:  # pragma: no cover
        """SSSD configuration manager."""
        return SSSDConfigManager()

    @cached_property
    def service(self) -> SystemctlServiceManager:  # pragma: no cover
        """SSSD service manager."""
        return SystemctlServiceManager("sssd")

    def add_tls_certs(self, integration_id: int, chain: Iterable[str]) -> None:
        """Add a TLS certificate chain to the machine.

        Args:
            integration_id: Integration ID associated with the new TLS certificate chain.
            chain: Iterable chain of TLS certificates to add to the machine.

        Raises:
            SSSDOpsError: Raised if an error occurs when adding the new TLS certificates.

        Notes:
            The TLS certificate chain should be provided by the ``ldap`` integration provider.
        """
        tls_cert_dir = Path(f"/usr/local/share/ca-certificates/{integration_id}")
        _logger.info("writing new tls certificate chain to directory `%s`", tls_cert_dir)
        tls_cert_dir.mkdir(mode=0o644, exist_ok=True)
        for i, cert in enumerate(chain):
            (tls_cert_dir / f"cert-{i}.crt").write_text(cert)

        _logger.info("updating machine tls certificates with `update-ca-certificates`")
        try:
            subprocess.check_output(
                ["update-ca-certificates"],
                stderr=subprocess.PIPE,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            raise SSSDOpsError(
                f"failed to add new tls certificates in `{tls_cert_dir}`. reason: {e}"
            ) from e

    def remove_tls_certs(self, integration_id: int) -> None:
        """Remove TLS certificates from the machine.

        Args:
            integration_id: Integration ID associated with TLS certificates to be removed.

        Raises:
            SSSDOpsError: Raised if an error occurs when removing the TLS certificates.
        """
        tls_cert_dir = Path(f"/usr/local/share/ca-certificates/{integration_id}")
        _logger.info("removing tls certificates in directory `%s`", tls_cert_dir)
        shutil.rmtree(tls_cert_dir, ignore_errors=True)

        _logger.info("refreshing machine tls certificates with `update-ca-certificates --fresh`")
        try:
            subprocess.check_output(
                ["update-ca-certificates", "--fresh"],
                stderr=subprocess.PIPE,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            raise SSSDOpsError(
                f"failed to remove tls certificates in `{tls_cert_dir}`. reason: {e}"
            ) from e
