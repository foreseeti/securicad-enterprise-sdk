# Copyright 2020-2021 Foreseeti AB <https://foreseeti.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import TYPE_CHECKING, Any, Dict, List

if TYPE_CHECKING:
    from securicad.enterprise.client import Client


class Metadata:
    def __init__(self, client: "Client") -> None:
        self.client = client

    def get_metadata(self) -> List[Dict[str, Any]]:
        metadata = self.client._get("metadata")
        metalist = []
        for asset, data in metadata["assets"].items():
            attacksteps = []
            for attackstep in data["attacksteps"]:
                attacksteps.append(
                    {
                        "name": attackstep["name"],
                        "description": attackstep["description"],
                    }
                )
            metalist.append(
                {
                    "name": asset,
                    "description": data["description"],
                    "attacksteps": attacksteps,
                }
            )
        return sorted(metalist, key=lambda asset: asset["name"])