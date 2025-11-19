#!/usr/bin/env just --justfile
# Copyright 2023-2025 Canonical Ltd.
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

uv := require("uv")

project_dir := justfile_directory()
src_dir := project_dir / "src"
tests_dir := project_dir / "tests"

export PY_COLORS := "1"
export PYTHONBREAKPOINT := "ipdb.set_trace"
export PYTHONPATH := project_dir + ":" + project_dir / "lib" + ":" + src_dir

uv_run := "uv run --frozen --extra dev"

[private]
default:
    @just help

# Regenerate uv.lock
[group("dev")]
lock:
    uv lock

# Create a development environment
[group("dev")]
env: lock
    uv sync --extra dev

# Upgrade uv.lock with the latest dependencies
[group("dev")]
upgrade:
    uv lock --upgrade

# Generate publishing token for Charmhub
[group("dev")]
generate-token:
    charmcraft login \
        --export=.charmhub.secret \
        --permission=package-manage-metadata \
        --permission=package-manage-releases \
        --permission=package-manage-revisions \
        --permission=package-view-metadata \
        --permission=package-view-releases \
        --permission=package-view-revisions \
        --ttl=31536000  # 365 days

# Apply coding style standards to code
[group("lint")]
fmt: lock
    {{uv_run}} ruff format {{src_dir}} {{tests_dir}}
    {{uv_run}} ruff check --fix {{src_dir}} {{tests_dir}}

# Check code against coding style standards
[group("lint")]
lint: lock
    {{uv_run}} codespell {{project_dir}}
    {{uv_run}} ruff check {{src_dir}} {{tests_dir}}

# Run static type checker on code
[group("lint")]
typecheck: lock
    {{uv_run}} pyright

# Run unit tests
[group("test")]
unit *args: lock
    #!/usr/bin/env bash
    set -euxo pipefail

    # Since tests are collected together by `pytest`, which means that all the import
    # statements will be executed together, the charm unit tests are run separately
    # from the utility module unit tests. The charm unit tests use a mocked `sssd` module
    # that will bork `sssd` module tests if they are all collected together rather than
    # run in isolated pytest processes.
    {{uv_run}} coverage run --parallel-mode \
        --source={{src_dir}} \
        -m pytest -v --tb native -s \
        {{args}} {{tests_dir / "unit" / "test_charm.py"}}
    {{uv_run}} coverage run --parallel-mode \
        --source={{src_dir}} \
        -m pytest -v --tb native -s --ignore-glob *charm.py \
        {{args}} {{tests_dir / "unit"}}
    {{uv_run}} coverage combine
    {{uv_run}} coverage report

# Run integration tests
[group("test")]
integration *args: lock
    #!/usr/bin/env bash
    set -euxo pipefail

    charmcraft -v pack
    mv sssd_*.charm sssd.charm
    export LOCAL_SSSD={{project_dir / "sssd.charm"}}
    {{uv_run}} pytest \
        -v \
        --tb native \
        -s \
        --log-cli-level=INFO \
        {{args}} \
        {{tests_dir / "integration"}}

# Show available recipes
help:
    @just --list --unsorted
