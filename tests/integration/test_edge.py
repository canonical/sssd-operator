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

"""BDD step definitions for SSSD lifecycle tests."""

import jubilant
from pytest_bdd import given, parsers, scenarios, then
from pytest_jubilant_bdd import Context

from constants import (
    BIND_PASSWORD,
    BIND_PASSWORD_SECRET,
    EDGE_FEATURES,
    LDAP_APP_NAME,
    LDAP_INTEGRATOR_APP_NAME,
)

scenarios(*EDGE_FEATURES)


@given("I configure 'ldap-integrator' with data from 'openldap'")
def configure_ldap_integrator(context: Context) -> None:
    """Configure `ldap-integrator` application with data from `openldap`."""
    sssd_model = context.get_juju("sssd")
    ldap_model = context.get_juju("ldap")

    # Wait for OpenLDAP server to become active.
    ldap_model.wait(lambda status: jubilant.all_active(status, LDAP_APP_NAME))

    # Ensure that cloud-init has finished initializing the LDAP server.
    try:
        ldap_model.exec("cloud-init status --wait", unit=f"{LDAP_APP_NAME}/0")
    except jubilant.TaskError as e:
        # cloud-init does not like the `apt_mirror` option added by Juju to new instances,
        # but it does not cause cloud-init to fail, so `cloud-init status --wait` returns
        # exit code 2 "Recoverable error - Cloud-init completed but experienced errors".
        assert e.task.return_code == 2

    # Create a Juju secret for the OpenLDAP server's bind password
    # and grant `ldap-integrator` access to the secret.
    password = sssd_model.add_secret(BIND_PASSWORD_SECRET, content={"password": BIND_PASSWORD})
    sssd_model.grant_secret(password, LDAP_INTEGRATOR_APP_NAME)

    # Configure `ldap-integrator` with information from OpenLDAP server.
    ldap_server_address = (
        ldap_model.status().apps[LDAP_APP_NAME].units[f"{LDAP_APP_NAME}/0"].public_address
    )
    sssd_model.config(
        LDAP_INTEGRATOR_APP_NAME,
        {
            "urls": f"ldap://{ldap_server_address},ldaps://{ldap_server_address}",
            "base_dn": "dc=test,dc=ubuntu,dc=com",
            "starttls": False,
            "bind_dn": "cn=admin,dc=test,dc=ubuntu,dc=com",
            "bind_password": password,
        },
    )


@then(parsers.parse("the output should be '{expected}'"))
def assert_output(context: Context, expected: str) -> None:
    """Assert the most recent exec result matches the expected output."""
    task = context.exec_results.peek()
    assert task.stdout.strip() == expected
