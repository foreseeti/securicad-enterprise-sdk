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

if TYPE_CHECKING:
    from securicad.enterprise.client import Client
    from securicad.enterprise.projects import Project
    from securicad.enterprise.users import User


class Organization:
    def __init__(self, client: "Client", tag: str, name: str) -> None:
        self.client = client
        self.tag = tag
        self.name = name

    @staticmethod
    def from_dict(client: "Client", dict_org: Dict[str, Any]) -> "Organization":
        return Organization(client=client, tag=dict_org["tag"], name=dict_org["name"])

    def update(self, *, name: str) -> None:
        data: Dict[str, Any] = {"tag": self.tag, "name": name}
        dict_org = self.client._post("organization", data)
        self.name = dict_org["name"]

    def delete(self) -> None:
        self.client._delete("organization", {"tag": self.tag})

    def list_users(self) -> List["User"]:
        dict_org = self.client.organizations._get_dict_organization_by_tag(self.tag)
        users = []
        for dict_user in dict_org["users"]:
            users.append(self.client.users.get_user_by_uid(dict_user["id"]))
        return users

    def list_projects(self) -> List["Project"]:
        dict_org = self.client.organizations._get_dict_organization_by_tag(self.tag)
        projects = []
        for dict_project in dict_org["projects"]:
            projects.append(
                self.client.projects.get_project_by_pid(dict_project["pid"])
            )
        return projects


class Organizations:
    def __init__(self, client: "Client") -> None:
        self.client = client

    def _list_dict_organizations(self) -> List[Dict[str, Any]]:
        dict_organizations = self.client._get("organization/all")
        return dict_organizations

    def _get_dict_organization_by_tag(self, tag: str) -> Dict[str, Any]:
        dict_organization = self.client._get(f"organization/{tag}")
        return dict_organization

    def list_organizations(self) -> List[Organization]:
        dict_orgs = self._list_dict_organizations()
        organizations = []
        for dict_org in dict_orgs:
            organizations.append(
                Organization.from_dict(client=self.client, dict_org=dict_org)
            )
        return organizations

    def get_organization_by_tag(self, tag: str) -> Organization:
        dict_org = self._get_dict_organization_by_tag(tag)
        return Organization.from_dict(client=self.client, dict_org=dict_org)

    def get_organization_by_name(self, name: str) -> Organization:
        organizations = self.list_organizations()
        for organization in organizations:
            if organization.name == name:
                return organization
        for organization in organizations:
            if organization.name.lower() == name.lower():
                return organization
        raise ValueError(f"Invalid organization {name}")

    def create_organization(
        self, name: str, license: Optional[str] = None
    ) -> Organization:
        data: Dict[str, Any] = {"name": name}
        if license is not None:
            data["license"] = license
        dict_org = self.client._put("organization", data)
        return Organization.from_dict(client=self.client, dict_org=dict_org)
