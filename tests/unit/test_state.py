#!/usr/bin/env python3
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

"""Unit tests for the `state` module."""

from unittest.mock import Mock

import ops
import pytest
from charmed_hpc_libs.ops.conditions import ConditionEvaluation

import state
from constants import LDAP_INTEGRATION_NAME


@pytest.mark.parametrize(
    "ldap_ok, is_active, expected_status",
    [
        pytest.param(
            False,
            True,
            ops.WaitingStatus(f"Waiting for integrations: [`{LDAP_INTEGRATION_NAME}`]"),
            id="waiting_when_ldap_integration_is_missing",
        ),
        pytest.param(
            True,
            False,
            ops.WaitingStatus("Waiting for `sssd` to start"),
            id="waiting_when_sssd_is_not_running",
        ),
        pytest.param(
            True,
            True,
            ops.ActiveStatus(),
            id="active_when_ldap_integration_exists_and_sssd_is_running",
        ),
    ],
)
def test_check_sssd(
    monkeypatch: pytest.MonkeyPatch,
    mock_sssd: Mock,
    ldap_ok: bool,
    is_active: bool,
    expected_status: ops.StatusBase,
) -> None:
    """Test `check_sssd` returns the correct unit status for each combination of conditions."""
    monkeypatch.setattr(state, "ldap_exists", lambda _charm: ConditionEvaluation(ok=ldap_ok))
    mock_sssd.is_active.return_value = is_active

    status = state.check_sssd(Mock())

    assert status == expected_status
    if not ldap_ok:
        mock_sssd.is_active.assert_not_called()
