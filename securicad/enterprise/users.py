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

from enum import Enum, unique
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from securicad.enterprise.client import Client
    from securicad.enterprise.organizations import Organization


@unique
class Role(Enum):
    USER = ["user"]
    PROJECT_CREATOR = ["user", "project_creator"]
    ADMIN = ["user", "project_creator", "admin"]
    SYSADMIN = ["user", "project_creator", "admin", "system_admin"]

    @staticmethod
    def from_list(roles: List[str]) -> "Role":
        for role in Role:
            if sorted(roles) == sorted(role.value):
                return role
        raise ValueError(f"Invalid role {roles}")


class User:
    def __init__(
        self,
        client: "Client",
        uid: int,
        username: str,
        firstname: str,
        lastname: str,
        role: Role,
        organization: Optional[str],
    ) -> None:
        self.client = client
        self.uid = uid
        self.username = username
        self.firstname = firstname
        self.lastname = lastname
        self.role = role
        self.organization = organization

    @staticmethod
    def from_dict(client: "Client", dict_user: Dict[str, Any]) -> "User":
        return User(
            client=client,
            uid=dict_user["uid"],
            username=dict_user["email"],
            firstname=dict_user["firstname"],
            lastname=dict_user["lastname"],
            role=Role.from_list(dict_user["roles"]),
            organization=dict_user["organization"],
        )

    def update(
        self,
        *,
        username: Optional[str] = None,
        password: Optional[str] = None,
        firstname: Optional[str] = None,
        lastname: Optional[str] = None,
    ) -> None:
        data: Dict[str, Any] = {
            "uid": self.uid,
            "email": self.username if username is None else username,
            "firstname": self.firstname if firstname is None else firstname,
            "lastname": self.lastname if lastname is None else lastname,
        }
        if password is not None:
            data["password"] = password
        dict_user = self.client._post("user", data)["user"]
        self.username = dict_user["email"]
        self.firstname = dict_user["firstname"]
        self.lastname = dict_user["lastname"]

    def delete(self) -> None:
        self.client._delete("user", {"uid": self.uid})

    def set_role(self, role: Role) -> None:
        to_add = [x for x in role.value if x not in self.role.value]
        to_remove = [x for x in self.role.value if x not in role.value]
        if to_add:
            self.client._put("user/roles", {"uid": self.uid, "roles": to_add})
        if to_remove:
            self.client._delete("user/roles", {"uid": self.uid, "roles": to_remove})
        self.role = role


class Users:
    def __init__(self, client: "Client") -> None:
        self.client = client

    def _list_dict_users(self) -> List[Dict[str, Any]]:
        dict_users = self.client._post("users")["users"]
        return dict_users

    def whoami(self) -> User:
        dict_user = self.client._get("whoami")
        dict_user["uid"] = dict_user["id"]
        return User.from_dict(client=self.client, dict_user=dict_user)

    def change_password(self, old_password: str, new_password: str) -> None:
        data: Dict[str, Any] = {
            "oldpassword": old_password,
            "newpassword": new_password,
        }
        access_token = self.client._post("changepwd", data)["access_token"]
        self.client._set_access_token(access_token)

    def list_users(self) -> List[User]:
        dict_users = self._list_dict_users()
        users = []
        for dict_user in dict_users:
            users.append(User.from_dict(client=self.client, dict_user=dict_user))
        return users

    def get_user_by_uid(self, uid: int) -> User:
        for user in self.list_users():
            if user.uid == uid:
                return user
        raise ValueError(f"Invalid user {uid}")

    def get_user_by_username(self, username: str) -> User:
        for user in self.list_users():
            if user.username == username:
                return user
        for user in self.list_users():
            if user.username.lower() == username.lower():
                return user
        raise ValueError(f"Invalid user {username}")

    def create_user(
        self,
        username: str,
        password: str,
        firstname: str,
        lastname: str,
        role: Role,
        organization: Optional["Organization"] = None,
    ) -> User:
        data: Dict[str, Any] = {
            "email": username,
            "password": password,
            "firstname": firstname,
            "lastname": lastname,
            "roles": role.value,
            "isactive": True,
        }
        if organization is not None:
            data["organization"] = organization.tag
        dict_user = self.client._put("user", data)
        return User.from_dict(client=self.client, dict_user=dict_user)
