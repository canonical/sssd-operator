#!/usr/bin/env python3
# Copyright 2025-2026 Canonical Ltd.
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

"""Unit tests for the ``sssd`` charm workload manager module."""

import configparser
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest
from pyfakefs.fake_filesystem import FakeFilesystem
from pyfakefs.helpers import set_gid, set_uid
from pytest_mock import MockerFixture

from sssd import SSSDConfigManager, SSSDManager, SSSDOpsError

MOCK_SEEDED_SSSD_CONFIG = """
[sssd]
config_file_version = 2
"""
MOCK_FULL_SSSD_CONFIG = """
[sssd]
config_file_version = 2
domains = ldap

[domain/ldap]
id_provider = ldap
auth_provider = ldap
ldap_uri = ldap://10.0.0.135:3893
ldap_search_base = dc=glauth,dc=com
ldap_default_bind_dn = cn=sssd,ou=sssd,dc=glauth,dc=com
ldap_default_authtok_type = password
ldap_default_authtok = 73402cd1453bdb98e8456aca6e858a48621dd3e716fbf7a5be6fa01d2fc8c944
ldap_use_tokengroups = False
ldap_group_member = member
ldap_schema = rfc2307bis
ldap_id_use_start_tls = True
cache_credentials = True
"""


@pytest.fixture(autouse=True)
def _set_root(fs: FakeFilesystem) -> None:
    """``sssd`` module functions run as root; set the fake filesystem uid/gid to 0."""
    set_uid(0)
    set_gid(0)


@pytest.fixture(scope="function")
def mock_run(mocker: MockerFixture) -> Mock:
    """Mock ``subprocess.run`` to return a successful completed process."""
    return mocker.patch(
        "subprocess.run", return_value=subprocess.CompletedProcess([], returncode=0)
    )


@pytest.fixture(scope="function")
def mock_sssd_manager(mocker: MockerFixture) -> SSSDManager:
    """Mock ``SSSDManager`` with the backing package and service manager patched out."""
    from charmed_hpc_libs.ops.machine import AptOpsManager

    mocker.patch.object(AptOpsManager, "install")
    mocker.patch.object(AptOpsManager, "remove")
    mocker.patch.object(AptOpsManager, "version", return_value="2.9.4-1.1ubuntu6.2")

    manager = SSSDManager()
    # Replace the ``service`` cached property so no real ``systemctl`` code runs.
    manager.__dict__["service"] = Mock(name="service")
    return manager


class TestSSSDConfigmanager:
    """Test the ``SSSDConfigManager`` class."""

    def test_read(self, fs: FakeFilesystem) -> None:
        """Test the ``read`` method."""
        fs.create_file("/etc/sssd/sssd.conf", contents=MOCK_FULL_SSSD_CONFIG)

        mock_parser = configparser.ConfigParser()
        mock_parser.read_string(MOCK_FULL_SSSD_CONFIG)
        mock_config_dict = {s: dict(mock_parser.items(s)) for s in mock_parser.keys()}

        config = SSSDConfigManager().read()
        config_dict = {s: dict(config.items(s)) for s in config.keys()}
        assert config_dict == mock_config_dict

    def test_edit(self, fs: FakeFilesystem) -> None:
        """Test the ``edit()`` context manager."""
        fs.create_file("/etc/sssd/sssd.conf", contents=MOCK_FULL_SSSD_CONFIG)

        mock_parser = configparser.ConfigParser()
        mock_parser.read_string(MOCK_FULL_SSSD_CONFIG)
        mock_config_dict = {s: dict(mock_parser.items(s)) for s in mock_parser.keys()}

        manager = SSSDConfigManager()
        with manager.edit() as config:
            assert dict(config["domain/ldap"]) == mock_config_dict["domain/ldap"]
            config["domain/ldap"]["ldap_id_use_start_tls"] = "False"
            config["domain/ldap"]["ldap_library_debug_level"] = "-1"

        config = manager.read()
        assert config["domain/ldap"]["ldap_id_use_start_tls"] == "False"
        assert config["domain/ldap"]["ldap_library_debug_level"] == "-1"

    def test_init(self, fs: FakeFilesystem) -> None:
        """Test the ``init()`` method."""
        SSSDConfigManager().init()
        assert fs.exists("/etc/sssd/sssd.conf")
        config = SSSDConfigManager().read()
        assert config["sssd"]["config_file_version"] == "2"

    def test_delete(self, fs: FakeFilesystem) -> None:
        """Test the ``delete()`` method."""
        fs.create_file("/etc/sssd/sssd.conf", contents=MOCK_FULL_SSSD_CONFIG)
        SSSDConfigManager().delete()
        assert not fs.exists("/etc/sssd/sssd.conf")

        # Deleting when the file does not exist should not raise.
        SSSDConfigManager().delete()

    def test_domains(self, fs: FakeFilesystem) -> None:
        """Test the ``domains()`` method."""
        fs.create_file("/etc/sssd/sssd.conf", contents=MOCK_FULL_SSSD_CONFIG)
        assert SSSDConfigManager().domains() == ["ldap"]

    def test_update_ldap_domain(self, mocker: MockerFixture, fs: FakeFilesystem) -> None:
        """Test the ``update_ldap_domain()`` method."""
        fs.create_file("/etc/sssd/sssd.conf", contents=MOCK_FULL_SSSD_CONFIG)

        ldap_data = mocker.MagicMock()
        ldap_data.urls = ["ldap://10.0.0.128:3893", "ldap://10.0.0.129:3893"]
        ldap_data.base_dn = "dc=glauth,dc=com"
        ldap_data.bind_dn = "cn=sssd,ou=sssd,dc=glauth,dc=com"
        ldap_data.bind_password = "supersecret"
        ldap_data.starttls = False

        # Test when `ldap` domain is already in `sssd.conf`.
        SSSDConfigManager().update_ldap_domain("ldap", ldap_data)
        config = SSSDConfigManager().read()
        assert dict(config["domain/ldap"]) == {
            "id_provider": "ldap",
            "auth_provider": "ldap",
            "ldap_uri": "ldap://10.0.0.128:3893,ldap://10.0.0.129:3893",
            "ldap_search_base": "dc=glauth,dc=com",
            "ldap_default_bind_dn": "cn=sssd,ou=sssd,dc=glauth,dc=com",
            "ldap_default_authtok_type": "password",
            "ldap_default_authtok": "supersecret",
            "ldap_use_tokengroups": "False",
            "ldap_group_member": "member",
            "ldap_schema": "rfc2307bis",
            "ldap_id_use_start_tls": "False",
            "cache_credentials": "True",
        }
        assert SSSDConfigManager().domains() == ["ldap"]

        fs.reset()
        fs.create_file("/etc/sssd/sssd.conf", contents=MOCK_SEEDED_SSSD_CONFIG)

        # Test when `polaris` domain is not in `sssd.conf`.
        SSSDConfigManager().update_ldap_domain("polaris", ldap_data)
        config = SSSDConfigManager().read()
        assert dict(config["domain/polaris"]) == {
            "id_provider": "ldap",
            "auth_provider": "ldap",
            "ldap_uri": "ldap://10.0.0.128:3893,ldap://10.0.0.129:3893",
            "ldap_search_base": "dc=glauth,dc=com",
            "ldap_default_bind_dn": "cn=sssd,ou=sssd,dc=glauth,dc=com",
            "ldap_default_authtok_type": "password",
            "ldap_default_authtok": "supersecret",
            "ldap_use_tokengroups": "False",
            "ldap_group_member": "member",
            "ldap_schema": "rfc2307bis",
            "ldap_id_use_start_tls": "False",
            "cache_credentials": "True",
        }
        assert SSSDConfigManager().domains() == ["polaris"]

    def test_remove_ldap_domain(self, mocker: MockerFixture, fs: FakeFilesystem) -> None:
        """Test the ``remove_ldap_domain()`` method."""
        fs.create_file("/etc/sssd/sssd.conf", contents=MOCK_FULL_SSSD_CONFIG)

        mock_parser = configparser.ConfigParser()
        mock_parser.read_string(MOCK_SEEDED_SSSD_CONFIG)
        mock_config_dict = {s: dict(mock_parser.items(s)) for s in mock_parser.keys()}

        # Test when there is only one domain in `sssd.conf`.
        SSSDConfigManager().remove_ldap_domain("ldap")
        config = SSSDConfigManager().read()
        config_dict = {s: dict(config.items(s)) for s in config.keys()}
        assert config_dict == mock_config_dict

        # Test when there are multiple domains in `sssd.conf`.
        fs.reset()
        fs.create_file("/etc/sssd/sssd.conf", contents=MOCK_FULL_SSSD_CONFIG)
        ldap_data = mocker.MagicMock()
        ldap_data.urls = ["ldap://10.0.0.128:3893", "ldap://10.0.0.129:3893"]
        ldap_data.base_dn = "dc=glauth,dc=com"
        ldap_data.bind_dn = "cn=sssd,ou=sssd,dc=glauth,dc=com"
        ldap_data.bind_password = "supersecret"
        ldap_data.starttls = True

        SSSDConfigManager().update_ldap_domain("polaris", ldap_data)
        SSSDConfigManager().remove_ldap_domain("ldap")
        assert len(SSSDConfigManager().domains()) == 1


class TestSSSDManager:
    """Test the ``SSSDManager`` class."""

    def test_add_tls_certs(
        self, mock_sssd_manager: SSSDManager, mock_run: Mock, fs: FakeFilesystem
    ) -> None:
        """Test the ``add_tls_certs()`` method."""
        # This directory must exist on every machine.
        fs.create_dir("/usr/local/share/ca-certificates")
        cert0 = "I'm super cert-0"
        cert1 = "I'm super cert-1"

        # Test when `SSSDManager.add_tls_certs()` succeeds with no errors.
        mock_sssd_manager.add_tls_certs(1, [cert0, cert1])
        assert mock_run.call_args[0][0] == ["update-ca-certificates"]
        assert Path("/usr/local/share/ca-certificates/1/cert-0.crt").read_text() == cert0
        assert Path("/usr/local/share/ca-certificates/1/cert-1.crt").read_text() == cert1

        # Test when `SSSDManager.add_tls_certs()` fails to update tls certificates.
        mock_run.side_effect = subprocess.CalledProcessError(returncode=1, cmd="")
        with pytest.raises(SSSDOpsError):
            mock_sssd_manager.add_tls_certs(1, [cert0, cert1])

    def test_remove_tls_certs(
        self, mock_sssd_manager: SSSDManager, mock_run: Mock, fs: FakeFilesystem
    ) -> None:
        """Test the ``remove_tls_certs()`` method."""
        # This directory must exist on every machine.
        fs.create_dir("/usr/local/share/ca-certificates")
        cert0 = "I'm super cert-0"
        cert1 = "I'm super cert-1"
        mock_sssd_manager.add_tls_certs(1, [cert0, cert1])

        # Test when `SSSDManager.remove_tls_certs()` succeeds with no errors.
        mock_sssd_manager.remove_tls_certs(1)
        assert mock_run.call_args[0][0] == ["update-ca-certificates", "--fresh"]
        assert not fs.exists("/usr/local/share/ca-certificates/1")

        # Test when `SSSDManager.remove_tls_certs()` fails to remove tls certificates.
        mock_run.side_effect = subprocess.CalledProcessError(returncode=1, cmd="")
        with pytest.raises(SSSDOpsError):
            mock_sssd_manager.remove_tls_certs(1)
