# Copyright 2025 Canonical Ltd.
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

"""Mock for the `sssd` module."""

import sys
import types
from collections.abc import Callable
from functools import wraps
from unittest.mock import Mock

from sssd import SSSDOpsError


def reset_mock_sssd_module(func: Callable[..., None]) -> Callable[..., None]:
    """Reset `sssd` module mocks before each test run.

    Notes:
        This method is needed because the mocked `sssd` module is treated
        as a global object, so modifications to a mock in one test will be
        present in another test.
    """

    @wraps(func)
    def wrapper(*args, **kwargs) -> None:
        [
            m.reset_mock(return_value=True, side_effect=True)
            for m in mock_sssd.__dict__.values()
            if isinstance(m, Mock)
        ]
        func(*args, **kwargs)

    return wrapper


module_name = "sssd"
mock_sssd = types.ModuleType("sssd")
sys.modules[module_name] = mock_sssd

mock_sssd.SSSDOpsError = SSSDOpsError
mock_sssd.install = Mock(name=module_name + ".install")
mock_sssd.remove = Mock(name=module_name + ".remove")
mock_sssd.version = Mock(name=module_name + ".version")
mock_sssd.active = Mock(name=module_name + ".active")
mock_sssd.restart = Mock(name=module_name + ".restart")
mock_sssd.enable = Mock(name=module_name + ".enable")
mock_sssd.disable = Mock(name=module_name + ".disable")
mock_sssd.read = Mock(name=module_name + ".read")
mock_sssd.edit = Mock(name=module_name + ".edit")
mock_sssd.domains = Mock(name=module_name + ".domains")
mock_sssd.add_ldap_domain = Mock(name=module_name + ".add_ldap_domain")
mock_sssd.update_ldap_domain = Mock(name=module_name + ".update_ldap_domain")
mock_sssd.remove_ldap_domain = Mock(name=module_name + ".remove_ldap_domain")
mock_sssd.add_tls_certs = Mock(name=module_name + ".add_tls_certs")
mock_sssd.remove_tls_certs = Mock(name=module_name + ".remove_tls_certs")
