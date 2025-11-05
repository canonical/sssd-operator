#!/usr/bin/env python3
# Copyright 2023-2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for sssd charm."""

import jubilant
import pytest

from constants import SSSD_APP_NAME, UBUNTU_APP_NAME


@pytest.mark.order(1)
@pytest.mark.parametrize("base", ["ubuntu@24.04"])
def test_build_and_deploy(juju: jubilant.Juju, base: str, sssd) -> None:
    """Test building and deploying the sssd charm."""
    # Deploy sssd charm (subordinate charm with 0 units)
    juju.deploy(
        sssd,
        SSSD_APP_NAME,
        base=base,
    )

    # Deploy ubuntu charm as principal
    juju.deploy(
        UBUNTU_APP_NAME,
        UBUNTU_APP_NAME,
        channel="latest/stable",
        base=base,
        num_units=1,
    )

    # Integrate sssd with ubuntu
    juju.integrate(SSSD_APP_NAME, UBUNTU_APP_NAME)

    # Wait for sssd to reach waiting status (waiting for ldap integration)
    juju.wait(
        lambda status: (
            status.applications.get(SSSD_APP_NAME)
            and status.applications[SSSD_APP_NAME].units
            and len(status.applications[SSSD_APP_NAME].units) > 0
            and list(status.applications[SSSD_APP_NAME].units.values())[0].workload_status.status == "waiting"
            and list(status.applications[SSSD_APP_NAME].units.values())[0].workload_status.message == "Waiting for integrations: [`ldap`]"
        )
    )

