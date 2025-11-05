#!/usr/bin/env python3
# Copyright 2023-2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Configure integration test run."""

import logging
import os
from collections.abc import Iterator
from pathlib import Path

import jubilant
import pytest

logger = logging.getLogger(__name__)
LOCAL_SSSD = Path(sssd) if (sssd := os.getenv("LOCAL_SSSD")) else None


@pytest.fixture(scope="session")
def juju(request: pytest.FixtureRequest) -> Iterator[jubilant.Juju]:
    """Yield wrapper for interfacing with the `juju` CLI command."""
    keep_models = bool(request.config.getoption("--keep-models"))

    with jubilant.temp_model(keep=keep_models) as juju:
        juju.wait_timeout = 10 * 60

        yield juju

        if request.session.testsfailed:
            log = juju.debug_log(limit=1000)
            print(log, end="")


@pytest.fixture(scope="module")
def base(request: pytest.FixtureRequest) -> str:
    """Get the base to deploy the `sssd` charm on."""
    return request.config.getoption("--base")


@pytest.fixture(scope="module")
def sssd() -> Path:
    """Get `sssd` charm to use for integration tests.

    If the `LOCAL_SSSD` environment variable is not set,
    the `sssd` charm will be built locally.

    Returns:
        `Path` object pointing to the locally built charm.
    """
    if LOCAL_SSSD:
        logger.info("using local `sssd` charm located at %s", LOCAL_SSSD)
        return LOCAL_SSSD

    logger.info("building `sssd` charm locally")
    # Build the charm using charmcraft
    import subprocess

    subprocess.run(["charmcraft", "pack"], check=True)
    # Find the built charm file
    charm_files = list(Path(".").glob("sssd_*.charm"))
    if not charm_files:
        raise RuntimeError("Failed to build sssd charm")
    return charm_files[0]


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add custom command-line options for pytest."""
    parser.addoption(
        "--base",
        action="store",
        default="ubuntu@24.04",
        help="the base to deploy the sssd charm on during the integration tests",
    )
    parser.addoption(
        "--keep-models",
        action="store_true",
        default=False,
        help="keep temporarily created models",
    )

