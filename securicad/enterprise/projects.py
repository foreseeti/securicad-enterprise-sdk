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

from enum import IntEnum, unique
from typing import TYPE_CHECKING, Any, BinaryIO, Dict, List, Optional

if TYPE_CHECKING:
    from securicad.enterprise.client import Client
    from securicad.enterprise.models import ModelInfo
    from securicad.enterprise.organizations import Organization
    from securicad.enterprise.scenarios import Scenario
    from securicad.enterprise.tunings import Tuning
    from securicad.enterprise.users import User


@unique
class AccessLevel(IntEnum):
    GUEST = 100
    USER = 180
    OWNER = 250
    ADMIN = 255

    @staticmethod
    def from_int(level: int) -> "AccessLevel":
        for access_level in AccessLevel:
            if level == access_level:
                return access_level
        raise ValueError(f"Invalid access level {level}")


class Project:
    def __init__(
        self,
        client: "Client",
        pid: str,
        name: str,
        description: str,
        access_level: AccessLevel,
    ) -> None:
        self.client = client
        self.pid = pid
        self.name = name
        self.description = description
        self.access_level = access_level

    @staticmethod
    def from_dict(client: "Client", dict_project: Dict[str, Any]) -> "Project":
        return Project(
            client=client,
            pid=dict_project["pid"],
            name=dict_project["name"],
            description=dict_project["description"],
            access_level=AccessLevel.from_int(dict_project["accesslevel"]),
        )

    def update(
        self, *, name: Optional[str] = None, description: Optional[str] = None
    ) -> None:
        data: Dict[str, Any] = {
            "pid": self.pid,
            "name": self.name if name is None else name,
            "description": self.description if description is None else description,
        }
        dict_project = self.client._post("project", data)
        self.name = dict_project["name"]
        self.description = dict_project["description"]

    def delete(self) -> None:
        self.client._delete("project", {"pid": self.pid})

    def list_users(self) -> List["User"]:
        dict_project = self.client.projects._get_dict_project_by_pid(self.pid)
        users = []
        for dict_user in dict_project["users"]:
            users.append(self.client.users.get_user_by_uid(dict_user["uid"]))
        return users

    def add_user(
        self, user: "User", access_level: Optional[AccessLevel] = None
    ) -> None:
        data: Dict[str, Any] = {"pid": self.pid, "uid": user.uid}
        if access_level is not None:
            data["accesslevel"] = int(access_level)
        self.client._put("project/user", data)

    def remove_user(self, user: "User") -> None:
        data: Dict[str, Any] = {"pid": self.pid, "uid": user.uid}
        self.client._delete("project/user", data)

    def get_access_level(self, user: "User") -> Optional[AccessLevel]:
        dict_project = self.client.projects._get_dict_project_by_pid(self.pid)
        for dict_user in dict_project["users"]:
            if dict_user["uid"] == user.uid:
                return AccessLevel.from_int(dict_user["accesslevel"])
        return None

    def set_access_level(self, user: "User", access_level: AccessLevel) -> None:
        data: Dict[str, Any] = {
            "pid": self.pid,
            "uid": user.uid,
            "accesslevel": int(access_level),
        }
        self.client._post("project/user", data)

    def list_models(self) -> List["ModelInfo"]:
        dict_projects = self.client.projects._list_dict_projects()
        models = []
        for dict_project in dict_projects:
            if dict_project["pid"] == self.pid:
                for dict_model in dict_project["models"]:
                    models.append(
                        self.client.models.get_model_by_mid(self, dict_model["mid"])
                    )
                break
        return models

    def import_models(self, model_infos: List["ModelInfo"]) -> None:
        mids = [model_info.mid for model_info in model_infos]
        data: Dict[str, Any] = {"pid": self.pid, "mids": mids}
        self.client._post("models/import", data)

    def upload_scad_model(
        self,
        filename: str,
        file_io: BinaryIO,
        description: Optional[str] = None,
    ) -> "ModelInfo":
        return self.client.models.upload_scad_model(
            project=self, filename=filename, file_io=file_io, description=description
        )

    def list_scenarios(self) -> List["Scenario"]:
        return self.client.scenarios.list_scenarios(self)

    def create_scenario(
        self,
        model_info: "ModelInfo",
        name: str,
        description: Optional[str] = None,
        tunings: Optional[List["Tuning"]] = None,
    ) -> "Scenario":
        return self.client.scenarios.create_scenario(
            project=self,
            model_info=model_info,
            name=name,
            description=description,
            tunings=tunings,
        )

    def list_tunings(self) -> List["Tuning"]:
        return self.client.tunings.list_tunings(self)


class Projects:
    def __init__(self, client: "Client") -> None:
        self.client = client

    def _list_dict_projects(self) -> List[Dict[str, Any]]:
        dict_projects = self.client._post("projects")
        return dict_projects

    def _get_dict_project_by_pid(self, pid: str) -> Dict[str, Any]:
        dict_project = self.client._post("project/data", {"pid": pid})
        return dict_project

    def list_projects(self) -> List[Project]:
        dict_projects = self._list_dict_projects()
        projects = []
        for dict_project in dict_projects:
            projects.append(
                Project.from_dict(client=self.client, dict_project=dict_project)
            )
        return projects

    def get_project_by_pid(self, pid: str) -> Project:
        dict_project = self._get_dict_project_by_pid(pid)
        return Project.from_dict(client=self.client, dict_project=dict_project)

    def get_project_by_name(self, name: str) -> Project:
        projects = self.list_projects()
        for project in projects:
            if project.name == name:
                return project
        for project in projects:
            if project.name.lower() == name.lower():
                return project
        raise ValueError(f"Invalid project {name}")

    def create_project(
        self,
        name: str,
        description: Optional[str] = None,
        organization: Optional["Organization"] = None,
    ) -> Project:
        data: Dict[str, Any] = {
            "name": name,
            "description": "" if description is None else description,
        }
        if organization is not None:
            data["organization"] = organization.tag
        dict_project = self.client._put("project", data)
        return self.get_project_by_pid(dict_project["pid"])
