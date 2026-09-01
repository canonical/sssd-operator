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

"""Observe the core lifecycle events of the SSSD charm."""

import logging
from typing import TYPE_CHECKING

import ops
from charmed_hpc_libs.errors import Error
from charmed_hpc_libs.ops import Observer, StopCharm, refresh

from state import check_sssd

if TYPE_CHECKING:
    from charm import SSSDCharm

_logger = logging.getLogger(__name__)
refresh = refresh(hook=check_sssd)


class LifecycleObserver(Observer):
    """Observe the core lifecycle events of the SSSD charm."""

    def __init__(self, charm: "SSSDCharm") -> None:
        super().__init__(charm)
        self.charm.framework.observe(self.charm.on.install, self._on_install)
        self.charm.framework.observe(self.charm.on.start, self._on_start)
        self.charm.framework.observe(self.charm.on.stop, self._on_stop)

    @refresh
    def _on_install(self, event: ops.InstallEvent) -> None:
        """Handle when the SSSD charm is installed on the unit."""
        self.charm.unit.status = ops.MaintenanceStatus("Installing SSSD")
        try:
            self.charm.sssd.install()
            self.charm.sssd.config.init()
            self.charm.unit.set_workload_version(self.charm.sssd.version())
        except Error as e:
            _logger.exception(e.message)
            event.defer()
            raise StopCharm(
                ops.BlockedStatus("Failed to install SSSD. See `juju debug-log` for details")
            )

    @refresh
    def _on_start(self, _: ops.StartEvent) -> None:
        """Handle when the SSSD charm is started up on the unit."""
        self.charm.unit.status = ops.MaintenanceStatus("Initializing SSSD")
        self.charm.unit.set_workload_version(self.charm.sssd.version())
        self.charm.sssd.config.init()
        self.charm.sssd.service.enable()

    def _on_stop(self, _: ops.StopEvent) -> None:
        """Handle when the SSSD unit is going to be torn down by Juju."""
        self.charm.unit.status = ops.MaintenanceStatus("Stopping SSSD")
        self.charm.sssd.service.stop()
        self.charm.unit.status = ops.MaintenanceStatus("Removing SSSD")
        self.charm.sssd.config.delete()
        self.charm.sssd.remove(purge=True)
        self.charm.unit.status = ops.MaintenanceStatus("SSSD removed")
