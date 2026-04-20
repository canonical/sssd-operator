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

import sssd


@pytest.fixture(scope="function")
def mock_sssd(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock all public functions of the `sssd` module with `monkeypatch`.

    Returns:
        A namespace object whose attributes are the individual Mock objects that
        mirror the attribute names on the real `sssd` module.
    """
    mocks = {
        "install": Mock(name="sssd.install"),
        "remove": Mock(name="sssd.remove"),
        "version": Mock(name="sssd.version"),
        "is_active": Mock(name="sssd.is_active"),
        "restart": Mock(name="sssd.restart"),
        "enable": Mock(name="sssd.enable"),
        "disable": Mock(name="sssd.disable"),
        "read": Mock(name="sssd.read"),
        "edit": Mock(name="sssd.edit"),
        "domains": Mock(name="sssd.domains"),
        "add_ldap_domain": Mock(name="sssd.add_ldap_domain"),
        "update_ldap_domain": Mock(name="sssd.update_ldap_domain"),
        "remove_ldap_domain": Mock(name="sssd.remove_ldap_domain"),
        "add_tls_certs": Mock(name="sssd.add_tls_certs"),
        "remove_tls_certs": Mock(name="sssd.remove_tls_certs"),
    }
    for name, mock in mocks.items():
        monkeypatch.setattr(sssd, name, mock)

    namespace = type("MockSSSD", (), mocks)()
    return namespace
