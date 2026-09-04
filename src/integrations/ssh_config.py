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

"""Observe ``ssh-config`` integration events for the SSSD charm."""

from typing import TYPE_CHECKING

import ops
from charmed_hpc_libs.ops import Observer, refresh
from charmed_openssh_ssh_config_interface import (
    SSHConfigConnectedEvent,
    SSHConfigData,
    SSHConfigProvider,
)

from constants import SSH_CONFIG_INTEGRATION_NAME
from state import check_sssd

if TYPE_CHECKING:
    from charm import SSSDCharm

refresh = refresh(hook=check_sssd)

_SSH_AUTHORIZED_KEYS_CONFIG = (
    "AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys\nAuthorizedKeysCommandUser nobody\n"
)


class SSHConfigObserver(Observer):
    """Observe ``ssh-config`` integration events for the SSSD charm."""

    def __init__(self, charm: "SSSDCharm") -> None:
        super().__init__(charm)

        self.ssh_config = SSHConfigProvider(self.charm, SSH_CONFIG_INTEGRATION_NAME)
        self.charm.framework.observe(
            self.ssh_config.on.ssh_config_connected, self._on_ssh_config_connected
        )

    @refresh
    def _on_ssh_config_connected(self, event: SSHConfigConnectedEvent) -> None:
        """Handle when an ``ssh-config`` requirer connects to the SSSD charm."""
        self.charm.unit.status = ops.MaintenanceStatus("Publishing SSH configuration")
        self.ssh_config.set_config_data(
            SSHConfigData(ssh_config=_SSH_AUTHORIZED_KEYS_CONFIG),
            integration_id=event.relation.id,
        )
