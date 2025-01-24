#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for sssd charm."""

import asyncio

import pytest
from pytest_operator.plugin import OpsTest

SSSD = "sssd"
BASE = ["ubuntu@24.04"]
UBUNTU = "ubuntu"


@pytest.mark.abort_on_fail
@pytest.mark.parametrize("base", BASE)
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest, base: str, sssd_charm) -> None:
    """Test building and deploying the sssd charm."""
    await asyncio.gather(
        ops_test.model.deploy(
            str(await sssd_charm),
            application_name=SSSD,
            num_units=0,
            base=base,
        ),
        ops_test.model.deploy(
            UBUNTU,
            channel="latest/stable",
            application_name=UBUNTU,
            num_units=1,
            base=base,
        ),
    )

    await ops_test.model.integrate(SSSD, UBUNTU)

    # Assert that sssd is waiting to be connected to an ldap provider.
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(apps=[SSSD], status="waiting", timeout=1000)
        assert ops_test.model.applications[SSSD].units[0].workload_status == "waiting"
        assert (
            ops_test.model.applications[SSSD].units[0].workload_status_message
            == "Waiting for integrations: [`ldap`]"
        )
