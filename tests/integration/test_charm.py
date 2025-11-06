#!/usr/bin/env python3
# Copyright 2023-2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for sssd charm."""

from pathlib import Path

import jubilant
import pytest

from constants import SSSD_APP_NAME, UBUNTU_APP_NAME


def _check_sssd_waiting(status: jubilant.Status) -> bool:
    """Check if sssd subordinate is in waiting state with correct message."""
    try:
        ubuntu_app = status.apps[UBUNTU_APP_NAME]
    except KeyError:
        return False
    if not ubuntu_app.units:
        return False
    ubuntu_unit = ubuntu_app.units[f"{UBUNTU_APP_NAME}/0"]
    try:
        sssd_unit = ubuntu_unit.subordinates[f"{SSSD_APP_NAME}/0"]
    except KeyError:
        return False
    return (
        sssd_unit.workload_status.current == "waiting"
        and sssd_unit.workload_status.message == "Waiting for integrations: [`ldap`]"
    )


@pytest.mark.order(1)
def test_deploy(juju: jubilant.Juju, base: str, sssd: Path | str) -> None:
    """Test deploying the sssd charm."""
    juju.deploy(
        sssd,
        SSSD_APP_NAME,
        base=base,
        num_units=0,
    )

    juju.deploy(
        "ubuntu",
        UBUNTU_APP_NAME,
        channel="latest/stable",
        base=base,
        num_units=1,
    )

    juju.integrate(SSSD_APP_NAME, UBUNTU_APP_NAME)

    juju.wait(_check_sssd_waiting)
