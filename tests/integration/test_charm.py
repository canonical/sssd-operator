#!/usr/bin/env python3
# Copyright 2023-2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for sssd charm."""

import jubilant
import pytest

from constants import SSSD_APP_NAME, UBUNTU_APP_NAME


@pytest.mark.order(1)
def test_build_and_deploy(juju: jubilant.Juju, base: str, sssd) -> None:
    """Test building and deploying the sssd charm."""
    # Deploy sssd charm (subordinate charm)
    juju.deploy(
        sssd,
        SSSD_APP_NAME,
        base=base,
    )

    # Deploy ubuntu charm as principal
    juju.deploy(
        "ubuntu",
        UBUNTU_APP_NAME,
        channel="latest/stable",
        base=base,
        num_units=1,
    )

    # Integrate sssd with ubuntu
    juju.integrate(SSSD_APP_NAME, UBUNTU_APP_NAME)

    # Wait for sssd subordinate to reach waiting status (waiting for ldap integration)
    # For subordinate charms, the unit appears under the principal's subordinates
    def check_sssd_waiting(status: jubilant.Status) -> bool:
        """Check if sssd subordinate is in waiting state with correct message."""
        if UBUNTU_APP_NAME not in status.apps:
            return False
        ubuntu_app = status.apps[UBUNTU_APP_NAME]
        if not ubuntu_app.units:
            return False
        # Get the first ubuntu unit
        ubuntu_unit = list(ubuntu_app.units.values())[0]
        # Check if sssd subordinate exists
        sssd_unit_name = f"{SSSD_APP_NAME}/0"
        if sssd_unit_name not in ubuntu_unit.subordinates:
            return False
        sssd_unit = ubuntu_unit.subordinates[sssd_unit_name]
        # Check status and message
        return (
            sssd_unit.workload_status.current == "waiting"
            and sssd_unit.workload_status.message == "Waiting for integrations: [`ldap`]"
        )

    juju.wait(check_sssd_waiting)


