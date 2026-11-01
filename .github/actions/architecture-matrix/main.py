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

# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "craft-platforms~=0.12.0",
#     "pyyaml",
# ]
# ///

"""Build a GitHub Actions matrix from the Charmcraft build plan."""

import json
import os
from pathlib import Path

import craft_platforms
import yaml


def supported_architectures(path: Path) -> list[str]:
    """Return unique build architectures from the Charmcraft build plan.

    Args:
        path: Path to the Charmcraft project file.

    Returns:
        Architectures in build-plan order.

    Raises:
        ValueError: If the Charmcraft project defines no platforms, or if a
            platform declares an invalid architecture.
        craft_platforms.CraftPlatformsError: If the platforms are otherwise
            invalid (for example, no base can be determined).
    """
    project = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(project, dict) or not project.get("platforms"):
        raise ValueError(f"No Charmcraft platforms found in {path}")

    architectures: list[str] = []
    for build_info in craft_platforms.get_build_plan("charmcraft", project_data=project):
        if build_info.build_on not in architectures:
            architectures.append(build_info.build_on)
    return architectures


def build_matrix(
    architectures: list[str], runners: dict[str, str]
) -> dict[str, list[dict[str, str]]]:
    """Build a GitHub Actions matrix object from architectures and runner labels.

    Args:
        architectures: Architectures to include in the matrix.
        runners: Mapping of architecture names to GitHub runner labels.

    Returns:
        Matrix object with one include entry per architecture.

    Raises:
        ValueError: If an architecture has no runner configured.
    """
    include: list[dict[str, str]] = []
    for architecture in architectures:
        runner = runners.get(architecture)
        if runner is None:
            raise ValueError(f"No runner configured for {architecture}")
        include.append({"architecture": architecture, "machine-type": runner})
    return {"include": include}


def main() -> None:
    """Write the matrix object to the GitHub action output."""
    architectures = supported_architectures(Path(os.environ["CHARMCRAFT_FILE"]))
    runners: dict[str, str] = json.loads(os.environ["RUNNERS_JSON"])
    encoded = json.dumps(build_matrix(architectures, runners))
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write(f"matrix={encoded}\n")
    print(encoded)


if __name__ == "__main__":
    main()
