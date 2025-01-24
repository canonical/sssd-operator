#!/usr/bin/env python3
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

"""Unit tests for the `sssd` charm module."""

import configparser
import subprocess
from pathlib import Path
from unittest.mock import patch

import charms.operator_libs_linux.v0.apt as apt
from pyfakefs.fake_filesystem_unittest import TestCase
from pyfakefs.helpers import set_gid, set_uid

import sssd

APT_SSSD_INFO = """Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name           Version            Architecture Description
+++-==============-==================-============-==============================================
ii  sssd           2.9.4-1.1ubuntu6.2 amd64        System Security Services Daemon -- metapackage
"""

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


class TestSSSD(TestCase):
    """Unit tests for the `sssd` charm module.

    Notes:
        `sssd` module functions are run as the root user within the charm,
        so the global uid and gid must be set to `0` in the fake filesystem.
    """

    def setUp(self) -> None:
        self.setUpPyfakefs()
        set_uid(0)
        set_gid(0)

    def test_sssd_ops_error(self) -> None:
        """Test `sssd.SSSDOpsError()` exception."""
        message = "an operation on the sssd service failed"
        try:
            raise sssd.SSSDOpsError(message)
        except sssd.SSSDOpsError as e:
            self.assertEqual(e.message, message)

    @patch("subprocess.run")
    @patch("charms.operator_libs_linux.v0.apt.add_package")
    def test_install(self, add_package, _) -> None:
        """Test `sssd.install()` function."""
        # Test when `sssd.install()` succeeds with no errors.
        sssd.install()
        self.assertListEqual(add_package.call_args[0][0], ["sssd", "sssd-ldap"])
        with sssd.edit() as config:
            self.assertEqual(config["sssd"]["config_file_version"], "2")

        # Test when `sssd.install()` fails to install `sssd` and `sssd-ldap`.
        add_package.side_effect = apt.PackageError("failed to install sssd!!")
        with self.assertRaises(sssd.SSSDOpsError):
            sssd.install()

    @patch("charms.operator_libs_linux.v0.apt.remove_package")
    def test_remove(self, remove_package) -> None:
        """Test `sssd.remove()` function."""
        # Test when `sssd.remove()` succeeds with no errors.
        sssd.remove()
        self.assertListEqual(remove_package.call_args[0][0], ["sssd", "sssd-ldap"])
        self.assertFalse(self.fs.exists(sssd.SSSD_CONFIG_FILE))

        # Test when `sssd.remove()` fails to remove `sssd` and `sssd-ldap`.
        remove_package.side_effect = apt.PackageNotFoundError("failed to remove sssd!!")
        with self.assertRaises(sssd.SSSDOpsError):
            sssd.remove()

    @patch("subprocess.run", return_value=subprocess.CompletedProcess([], returncode=0))
    def test_version(self, subcmd) -> None:
        """Test `sssd.version()` function."""
        # Test `sssd.version()` when sssd is installed.
        subcmd.side_effect = [
            subprocess.CompletedProcess([], returncode=0, stdout="amd64"),
            subprocess.CompletedProcess([], returncode=0, stdout=APT_SSSD_INFO),
        ]
        self.assertEqual(sssd.version(), "2.9.4-1.1ubuntu6.2")
        self.assertListEqual(subcmd.call_args[0][0], ["dpkg", "-l", "sssd"])

        # Test `sssd.version()` when sssd is not installed.
        subcmd.side_effect = [
            subprocess.CompletedProcess([], returncode=0, stdout="amd64"),
            subprocess.CompletedProcess([], returncode=1),
        ]
        with self.assertRaises(sssd.SSSDOpsError):
            sssd.version()

    @patch("subprocess.run", return_value=subprocess.CompletedProcess([], returncode=0))
    def test_active(self, subcmd) -> None:
        """Test `sssd.active()` function."""
        sssd.active()
        self.assertListEqual(subcmd.call_args[0][0], ["systemctl", "--quiet", "is-active", "sssd"])

    @patch("subprocess.run", return_value=subprocess.CompletedProcess([], returncode=0))
    def test_restart(self, subcmd) -> None:
        """Test `sssd.restart()` function."""
        sssd.restart()
        self.assertListEqual(subcmd.call_args[0][0], ["systemctl", "restart", "sssd"])

    @patch("subprocess.run", return_value=subprocess.CompletedProcess([], returncode=0))
    def test_enable(self, subcmd) -> None:
        """Test `sssd.enable()` function."""
        sssd.enable()
        self.assertListEqual(subcmd.call_args[0][0], ["systemctl", "enable", "--now", "sssd"])

    @patch("subprocess.run", return_value=subprocess.CompletedProcess([], returncode=0))
    def test_disable(self, subcmd) -> None:
        """Test `sssd.disable()` function."""
        sssd.disable()
        self.assertListEqual(subcmd.call_args[0][0], ["systemctl", "disable", "--now", "sssd"])

    def test_read(self) -> None:
        """Test `sssd.read()` function."""
        self.fs.create_file("/etc/sssd/sssd.conf", contents=MOCK_FULL_SSSD_CONFIG)
        mock_parser = configparser.ConfigParser()
        mock_parser.read_string(MOCK_FULL_SSSD_CONFIG)
        mock_config_dict = {s: dict(mock_parser.items(s)) for s in mock_parser.keys()}

        config = sssd.read()
        config_dict = {s: dict(config.items(s)) for s in config.keys()}
        self.assertDictEqual(config_dict, mock_config_dict)

    def test_edit(self) -> None:
        """Test `sssd.edit()` context manager."""
        self.fs.create_file("/etc/sssd/sssd.conf", contents=MOCK_FULL_SSSD_CONFIG)
        mock_parser = configparser.ConfigParser()
        mock_parser.read_string(MOCK_FULL_SSSD_CONFIG)
        mock_config_dict = {s: dict(mock_parser.items(s)) for s in mock_parser.keys()}

        with sssd.edit() as config:
            self.assertDictEqual(dict(config["domain/ldap"]), mock_config_dict["domain/ldap"])
            config["domain/ldap"]["ldap_id_use_start_tls"] = "False"
            config["domain/ldap"]["ldap_library_debug_level"] = "-1"

        config = sssd.read()
        self.assertEqual(config["domain/ldap"]["ldap_id_use_start_tls"], "False")
        self.assertEqual(config["domain/ldap"]["ldap_library_debug_level"], "-1")

    def test_domains(self) -> None:
        """Test `sssd.domains()` function."""
        self.fs.create_file("/etc/sssd/sssd.conf", contents=MOCK_FULL_SSSD_CONFIG)
        self.assertListEqual(sssd.domains(), ["ldap"])

    @patch("charms.glauth_k8s.v0.ldap.LdapProviderData")
    def test_add_ldap_domain(self, ldap_data) -> None:
        """Test `sssd.add_ldap_domain()` function."""
        self.fs.create_file("/etc/sssd/sssd.conf", contents=MOCK_FULL_SSSD_CONFIG)
        ldap_data.urls = ["ldap://10.0.0.128:3893", "ldap://10.0.0.129:3893"]
        ldap_data.base_dn = "dc=glauth,dc=com"
        ldap_data.bind_dn = "cn=sssd,ou=sssd,dc=glauth,dc=com"
        ldap_data.bind_password = "supersecret"
        ldap_data.starttls = True

        sssd.add_ldap_domain("polaris", ldap_data)
        config = sssd.read()
        self.assertDictEqual(
            dict(config["domain/polaris"]),
            {
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
                "ldap_id_use_start_tls": "True",
                "cache_credentials": "True",
            },
        )
        self.assertListEqual(sssd.domains(), ["ldap", "polaris"])

    @patch("charms.glauth_k8s.v0.ldap.LdapProviderData")
    def test_update_ldap_domain(self, ldap_data) -> None:
        """Test `sssd.update_ldap_domain()` function."""
        self.fs.create_file("/etc/sssd/sssd.conf", contents=MOCK_FULL_SSSD_CONFIG)
        ldap_data.urls = ["ldap://10.0.0.128:3893", "ldap://10.0.0.129:3893"]
        ldap_data.base_dn = "dc=glauth,dc=com"
        ldap_data.bind_dn = "cn=sssd,ou=sssd,dc=glauth,dc=com"
        ldap_data.bind_password = "supersecret"
        ldap_data.starttls = False

        # Test when `ldap` domain is already in `sssd.conf`.
        sssd.update_ldap_domain("ldap", ldap_data)
        config = sssd.read()
        self.assertDictEqual(
            dict(config["domain/ldap"]),
            {
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
            },
        )
        self.assertListEqual(sssd.domains(), ["ldap"])

        self.fs.reset()
        self.fs.create_file("/etc/sssd/sssd.conf", contents=MOCK_SEEDED_SSSD_CONFIG)

        # Test when `polaris` domain is not in `sssd.conf`.
        sssd.update_ldap_domain("polaris", ldap_data)
        config = sssd.read()
        self.assertDictEqual(
            dict(config["domain/polaris"]),
            {
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
            },
        )
        self.assertListEqual(sssd.domains(), ["polaris"])

    @patch("charms.glauth_k8s.v0.ldap.LdapProviderData")
    def test_remove_ldap_domain(self, ldap_data) -> None:
        """Test `sssd.remove_ldap_domain()` function."""
        self.fs.create_file("/etc/sssd/sssd.conf", contents=MOCK_FULL_SSSD_CONFIG)
        mock_parser = configparser.ConfigParser()
        mock_parser.read_string(MOCK_SEEDED_SSSD_CONFIG)
        mock_config_dict = {s: dict(mock_parser.items(s)) for s in mock_parser.keys()}

        # Test when there is only one domain in `sssd.conf`.
        sssd.remove_ldap_domain("ldap")
        config = sssd.read()
        config_dict = {s: dict(config.items(s)) for s in config.keys()}
        self.assertDictEqual(config_dict, mock_config_dict)

        # Test when there are multiple domains in `sssd.conf`
        self.fs.reset()
        self.fs.create_file("/etc/sssd/sssd.conf", contents=MOCK_FULL_SSSD_CONFIG)
        ldap_data.urls = ["ldap://10.0.0.128:3893", "ldap://10.0.0.129:3893"]
        ldap_data.base_dn = "dc=glauth,dc=com"
        ldap_data.bind_dn = "cn=sssd,ou=sssd,dc=glauth,dc=com"
        ldap_data.bind_password = "supersecret"
        ldap_data.starttls = True

        sssd.add_ldap_domain("polaris", ldap_data)
        sssd.remove_ldap_domain("ldap")
        self.assertEqual(len(sssd.domains()), 1)

    @patch("subprocess.run", return_value=subprocess.CompletedProcess([], returncode=0))
    def test_add_tls_certs(self, subcmd) -> None:
        """Test `sssd.add_tls_certs()` function."""
        # This directory must exist on every machine.
        self.fs.create_dir("/usr/local/share/ca-certificates")
        cert0 = "I'm super cert-0"
        cert1 = "I'm super cert-1"

        # Test when `sssd.add_tls_certs()` succeeds with no errors.
        sssd.add_tls_certs(1, [cert0, cert1])
        self.assertListEqual(subcmd.call_args[0][0], ["update-ca-certificates"])
        self.assertEqual(Path("/usr/local/share/ca-certificates/1/cert-0.crt").read_text(), cert0)
        self.assertEqual(Path("/usr/local/share/ca-certificates/1/cert-1.crt").read_text(), cert1)

        # Test when `sssd.add_tls_certs()` fails to update tls certificates.
        subcmd.side_effect = subprocess.CalledProcessError(returncode=1, cmd="")
        with self.assertRaises(sssd.SSSDOpsError):
            sssd.add_tls_certs(1, [cert0, cert1])

    @patch("subprocess.run", return_value=subprocess.CompletedProcess([], returncode=0))
    def test_remove_tls_certs(self, subcmd) -> None:
        """Test `sssd.remove_tls_certs()` function."""
        # This directory must exist on every machine.
        self.fs.create_dir("/usr/local/share/ca-certificates")
        cert0 = "I'm super cert-0"
        cert1 = "I'm super cert-1"
        sssd.add_tls_certs(1, [cert0, cert1])

        # Test when `sssd.remove_tls_certs()` succeeds with no errors.
        sssd.remove_tls_certs(1)
        self.assertListEqual(subcmd.call_args[0][0], ["update-ca-certificates", "--fresh"])
        self.assertFalse(self.fs.exists("/usr/local/share/ca-certificates/1"))

        # Test when `sssd.remove_tls_certs()` fails to remove tls certificates.
        subcmd.side_effect = subprocess.CalledProcessError(returncode=1, cmd="")
        with self.assertRaises(sssd.SSSDOpsError):
            sssd.remove_tls_certs(1)
