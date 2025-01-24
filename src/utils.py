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

"""Utilities used within the SSSD charmed operator."""

from collections.abc import Callable
from functools import wraps
from typing import Any

import ops

import sssd
from constants import CERTIFICATES_TRANSFER_INTEGRATION_NAME, LDAP_INTEGRATION_NAME


class StopCharm(Exception):  # noqa N818
    """Exception raised if charm event hook is pre-maturely stopped."""

    @property
    def status(self) -> ops.StatusBase:
        """Return charm status pass as argument to exception."""
        return self.args[0]


def integration_exists(name: str) -> Callable[[ops.CharmBase], bool]:
    """Check if an integration exists.

    Args:
        name: Name of integration to check existence of.
    """

    def wrapper(charm: ops.CharmBase) -> bool:
        return bool(charm.model.relations[name])

    return wrapper


ldap_integration_exists = integration_exists(LDAP_INTEGRATION_NAME)
certificates_transfer_integration_exists = integration_exists(
    CERTIFICATES_TRANSFER_INTEGRATION_NAME
)


def refresh(func: Callable[..., None]) -> Callable[..., None]:
    """Refresh charm state after running an event handler method."""

    @wraps(func)
    def wrapper(charm: ops.CharmBase, *args: Any, **kwargs: Any) -> None:
        try:
            func(charm, *args, **kwargs)
        except StopCharm as e:
            charm.unit.status = e.status
            return

        if not ldap_integration_exists(charm):
            charm.unit.status = ops.WaitingStatus(
                f"Waiting for integrations: [`{LDAP_INTEGRATION_NAME}`]"
            )
            return

        if sssd.active():
            charm.unit.status = ops.ActiveStatus()
        else:
            charm.unit.status = ops.BlockedStatus("SSSD not running")

    return wrapper
