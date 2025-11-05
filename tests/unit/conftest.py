# Copyright 2023-2025 Canonical Ltd.
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

"""Configure unit tests for the `sssd` charm."""

import sys
import types
from unittest.mock import Mock

import pytest
from ops import testing
from pyfakefs.helpers import set_gid, set_uid

import sssd
from charm import SSSDCharm


@pytest.fixture(scope="function")
def mock_charm() -> testing.Context[SSSDCharm]:
    """Mock `SSSDCharm`."""
    return testing.Context(SSSDCharm)


@pytest.fixture(scope="function")
def mock_sssd(monkeypatch):
    """Mock the `sssd` module for charm tests."""
    # Create a mock module
    module_name = "sssd"
    mock_module = types.ModuleType(module_name)
    
    # Add the exception class (not mocked)
    mock_module.SSSDOpsError = sssd.SSSDOpsError
    
    # Add all the mocked functions
    mock_module.install = Mock(name=module_name + ".install")
    mock_module.remove = Mock(name=module_name + ".remove")
    mock_module.version = Mock(name=module_name + ".version")
    mock_module.active = Mock(name=module_name + ".active")
    mock_module.restart = Mock(name=module_name + ".restart")
    mock_module.enable = Mock(name=module_name + ".enable")
    mock_module.disable = Mock(name=module_name + ".disable")
    mock_module.read = Mock(name=module_name + ".read")
    mock_module.edit = Mock(name=module_name + ".edit")
    mock_module.domains = Mock(name=module_name + ".domains")
    mock_module.add_ldap_domain = Mock(name=module_name + ".add_ldap_domain")
    mock_module.update_ldap_domain = Mock(name=module_name + ".update_ldap_domain")
    mock_module.remove_ldap_domain = Mock(name=module_name + ".remove_ldap_domain")
    mock_module.add_tls_certs = Mock(name=module_name + ".add_tls_certs")
    mock_module.remove_tls_certs = Mock(name=module_name + ".remove_tls_certs")
    
    # Replace the module in sys.modules
    monkeypatch.setitem(sys.modules, module_name, mock_module)
    
    # Force reimport of charm to use the mocked sssd module
    import importlib
    import charm as charm_module
    importlib.reload(charm_module)
    
    return mock_module


@pytest.fixture(scope="function")
def fs(fs):
    """Configure fake filesystem for sssd module tests."""
    set_uid(0)
    set_gid(0)
    return fs
