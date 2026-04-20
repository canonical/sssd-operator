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

"""Manage the state of the SSSD charmed operator."""

from typing import TYPE_CHECKING

import ops
from charmed_hpc_libs.ops import integration_exists

import sssd
from constants import CERTIFICATES_TRANSFER_INTEGRATION_NAME, LDAP_INTEGRATION_NAME

if TYPE_CHECKING:
    from charm import SSSDCharm


# Check if the `certificates_transfer` integration exists.
certificates_transfer_exists = integration_exists(CERTIFICATES_TRANSFER_INTEGRATION_NAME)

# Check if the `ldap` integration exists.
ldap_exists = integration_exists(LDAP_INTEGRATION_NAME)


def check_sssd(charm: "SSSDCharm") -> ops.StatusBase:
    """Determine the state of the SSSD application/unit based on satisfied conditions."""
    if not ldap_exists(charm).ok:
        return ops.WaitingStatus(f"Waiting for integrations: [`{LDAP_INTEGRATION_NAME}`]")

    if not sssd.is_active():
        return ops.WaitingStatus("Waiting for `sssd` to start")

    return ops.ActiveStatus()
