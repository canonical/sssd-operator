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

"""Configure unit tests for the SSSD charm."""

from unittest.mock import Mock

import pytest
from charmed_hpc_libs.ops.machine import AptOpsManager
from ops import testing

import sssd
from charm import SSSDCharm


@pytest.fixture(scope="function")
def mock_charm() -> testing.Context[SSSDCharm]:
    """Mock ``SSSDCharm``."""
    return testing.Context(SSSDCharm)


@pytest.fixture(scope="function")
def mock_sssd(monkeypatch: pytest.MonkeyPatch) -> "Mock":
    """Mock the ``SSSDManager`` class used by the charm's observers."""
    install_mock = Mock(name="install")
    remove_mock = Mock(name="remove")
    version_mock = Mock(name="version", return_value="2.9.4-1.1ubuntu6.2")
    add_tls_certs_mock = Mock(name="add_tls_certs")
    remove_tls_certs_mock = Mock(name="remove_tls_certs")

    monkeypatch.setattr(AptOpsManager, "install", install_mock)
    monkeypatch.setattr(AptOpsManager, "remove", remove_mock)
    monkeypatch.setattr(AptOpsManager, "version", version_mock)

    service_mock = Mock(name="service")
    config_mock = Mock(name="config")
    monkeypatch.setattr(sssd.SSSDManager, "service", service_mock)
    monkeypatch.setattr(sssd.SSSDManager, "config", config_mock)

    monkeypatch.setattr(sssd.SSSDManager, "add_tls_certs", add_tls_certs_mock)
    monkeypatch.setattr(sssd.SSSDManager, "remove_tls_certs", remove_tls_certs_mock)

    return type(
        "MockSSSD",
        (),
        {
            "install": install_mock,
            "remove": remove_mock,
            "version": version_mock,
            "service": service_mock,
            "config": config_mock,
            "add_tls_certs": add_tls_certs_mock,
            "remove_tls_certs": remove_tls_certs_mock,
        },
    )()
