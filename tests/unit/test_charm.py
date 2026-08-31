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

"""Unit tests for the ``SSSDCharm`` entrypoint wiring."""

from ops import testing

import sssd
from charm import SSSDCharm
from integrations import CertificateTransferObserver, LdapObserver
from operations import LifecycleObserver


def test_charm_wiring() -> None:
    """Test that ``SSSDCharm.__init__`` wires the workload manager and observers.

    ``SSSDCharm`` is an entrypoint only - it must instantiate the ``SSSDManager``
    workload manager and the three observers (``LdapObserver``,
    ``CertificateTransferObserver``, ``LifecycleObserver``) and nothing else.
    """
    ctx = testing.Context(SSSDCharm)
    with ctx(ctx.on.update_status(), testing.State()) as manager:
        charm = manager.charm
        assert isinstance(charm.sssd, sssd.SSSDManager)
        assert isinstance(charm.ldap, LdapObserver)
        assert isinstance(charm.certificates, CertificateTransferObserver)
        assert isinstance(charm.lifecycle, LifecycleObserver)

        assert not any(
            name.startswith("_on_") and callable(getattr(SSSDCharm, name, None))
            for name in SSSDCharm.__dict__
        )
