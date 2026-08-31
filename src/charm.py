#!/usr/bin/env python3
# Copyright 2023-2026 Canonical Ltd.
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

"""Charmed operator for SSSD, the System Security Services Daemon."""

import ops

from integrations import CertificateTransferObserver, LdapObserver
from operations import LifecycleObserver
from sssd import SSSDManager


class SSSDCharm(ops.CharmBase):
    """Charmed operator for SSSD, the System Security Services Daemon."""

    def __init__(self, framework: ops.Framework) -> None:
        super().__init__(framework)

        self.sssd = SSSDManager()
        self.lifecycle = LifecycleObserver(self)

        self.ldap = LdapObserver(self)
        self.certificates = CertificateTransferObserver(self)


if __name__ == "__main__":  # pragma: nocover
    ops.main(SSSDCharm)
