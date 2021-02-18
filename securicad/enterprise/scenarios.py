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

from typing import TYPE_CHECKING, Any, Dict, List, Optional

from securicad.enterprise.simulations import Simulation

if TYPE_CHECKING:
    from securicad.enterprise.client import Client
    from securicad.enterprise.models import ModelInfo
    from securicad.enterprise.projects import Project


class Scenario:
    def __init__(
        self, client: "Client", pid: str, tid: str, name: str, description: str
    ) -> None:
        self.client = client
        self.pid = pid
        self.tid = tid
        self.name = name
        self.description = description

    @staticmethod
    def from_dict(client: "Client", dict_scenario: Dict[str, Any]) -> "Scenario":
        return Scenario(
            client=client,
            pid=dict_scenario["pid"],
            tid=dict_scenario["tid"],
            name=dict_scenario["name"],
            description=dict_scenario["description"],
        )

    def update(
        self, *, name: Optional[str] = None, description: Optional[str] = None
    ) -> None:
        data: Dict[str, Any] = {
            "pid": self.pid,
            "tid": self.tid,
            "name": self.name if name is None else name,
            "description": self.description if description is None else description,
        }
        response = self.client._post("scenario", data)
        self.name = response["name"]
        self.description = response["description"]

    def delete(self) -> None:
        data: Dict[str, Any] = {"pid": self.pid, "tids": [self.tid]}
        self.client._delete("scenarios", data)

    def list_simulations(self) -> List[Simulation]:
        dict_scenario = self.client.scenarios._get_dict_scenario_by_tid(
            self.pid, self.tid
        )
        simulations = []
        for dict_simulation in dict_scenario["results"].values():
            simulations.append(
                Simulation.from_dict(
                    client=self.client, dict_simulation=dict_simulation
                )
            )
        return simulations


class Scenarios:
    def __init__(self, client: "Client") -> None:
        self.client = client

    def _list_dict_scenarios(self, pid: str) -> Dict[str, Dict[str, Any]]:
        dict_scenarios = self.client._post("scenarios", {"pid": pid})
        return dict_scenarios

    def _get_dict_scenario_by_tid(self, pid: str, tid: str) -> Dict[str, Any]:
        data: Dict[str, Any] = {"pid": pid, "tid": tid}
        dict_scenario = self.client._post("scenario/data", data)
        return dict_scenario

    def list_scenarios(self, project: "Project") -> List[Scenario]:
        dict_scenarios = self._list_dict_scenarios(project.pid)
        scenarios = []
        for dict_scenario in dict_scenarios.values():
            scenarios.append(
                Scenario.from_dict(client=self.client, dict_scenario=dict_scenario)
            )
        return scenarios

    def get_scenario_by_tid(self, project: "Project", tid: str) -> Scenario:
        dict_scenario = self._get_dict_scenario_by_tid(project.pid, tid)
        return Scenario.from_dict(client=self.client, dict_scenario=dict_scenario)

    def get_scenario_by_name(self, project: "Project", name: str) -> Scenario:
        scenarios = self.list_scenarios(project)
        for scenario in scenarios:
            if scenario.name == name:
                return scenario
        for scenario in scenarios:
            if scenario.name.lower() == name.lower():
                return scenario
        raise ValueError(f"Invalid scenario {name}")

    def create_scenario(
        self,
        project: "Project",
        model_info: "ModelInfo",
        name: str,
        description: Optional[str] = None,
    ) -> Scenario:
        data: Dict[str, Any] = {
            "pid": project.pid,
            "mid": model_info.mid,
            "name": name,
            "description": "" if description is None else description,
        }
        dict_scenario = self.client._put("scenario", data)
        return Scenario.from_dict(client=self.client, dict_scenario=dict_scenario)
