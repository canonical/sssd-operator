#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Provides sssd class to control sssd."""

import logging
import os
import pathlib
import subprocess

from charms.operator_libs_linux.v0 import apt
from charms.operator_libs_linux.v1 import systemd
from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)


def available() -> bool:
    """Return if sssd is available or not."""
    try:
        apt.DebianPackage.from_installed_package("sssd-ldap")
        apt.DebianPackage.from_installed_package("ldap-utils")
        return True
    except apt.PackageNotFoundError as e:
        logger.debug(f"{e.message.split()[-1]} is not installed...")
        return False


def disable() -> None:
    """Disable services."""
    systemd.service_pause("sssd")


def enable() -> None:
    """Enable services."""
    systemd.service_resume("sssd")


def install() -> None:
    """Install using charmlib apt."""
    try:
        apt.update()
        apt.add_package("ldap-utils")
        apt.add_package("sssd-ldap")
    except apt.PackageNotFoundError as e:
        logger.error("a specified package not found in package cache or on system")
        raise e
    except apt.PackageError as e:
        logger.error("Could not install packages.")
        raise e


def remove() -> None:
    """Remove packages."""
    try:
        apt.remove_package("ldap-utils")
        apt.remove_package("sssd-ldap")
    except apt.PackageNotFoundError as e:
        logger.error("a specified package to remove is not found in package cache or on system")
        raise e


def remove_ca_cert() -> None:
    """Remove CA certificate."""
    pathlib.Path("/usr/local/share/ca-certificates/glauth.crt").unlink(missing_ok=True)
    try:
        subprocess.run(
            ["update-ca-certificates", "--fresh"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"{e} Reason:\n{e.stderr}")


def remove_conf() -> None:
    """Remove sssd configuration."""
    pathlib.Path("/etc/sssd/conf.d/sssd.conf").unlink(missing_ok=True)


def restart() -> None:
    """Restart servers/services."""
    systemd.service_restart("sssd")


def running() -> bool:
    """Return if sssd is running or not."""
    if not systemd.service_running("sssd"):
        return False
    return True


def save_ca_cert(ca_cert: str) -> None:
    """Save CA certificate.

    Args:
        ca_cert: CA certificate.
    """
    with open("/usr/local/share/ca-certificates/glauth.crt", "w") as f:
        f.write(ca_cert)

    try:
        subprocess.run(
            ["update-ca-certificates"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"{e} Reason:\n{e.stderr}")


def save_conf(
    basedn: str, domain: str, ldap_uri: str, ldap_default_bind_dn: str, ldap_password: str
) -> None:
    """Save sssd conf.

    sssd.conf file is generated from a pre-defined Jinja template.

    Args:
        basedn:   Default base DN.
        domain:   Domain name.
        ldap_uri: LDAPS address.
        ldap_default_bind_dn: Default bind DN from secret.
        ldap_password: Password passed from secret.
    """
    sssd_conf_path = "/etc/sssd/conf.d/sssd.conf"
    environment = Environment(loader=FileSystemLoader("src/templates"))
    template = environment.get_template("sssd.conf.j2")
    sssd_conf = template.render(
        basedn=basedn,
        domain=domain,
        ldap_uri=ldap_uri,
        ldap_default_bind_dn=ldap_default_bind_dn,
        ldap_password=ldap_password,
    )
    pathlib.Path(sssd_conf_path).write_text(sssd_conf)
    os.chown(sssd_conf_path, 0, 0)
    os.chmod(sssd_conf_path, 0o600)


def start() -> None:
    """Start services."""
    systemd.service_start("sssd")


def stop() -> None:
    """Stop services."""
    systemd.service_stop("sssd")
