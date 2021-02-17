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

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Optional
from urllib.parse import urljoin

import conftest

# isort: off

sys.path.append(str(Path(__file__).resolve().parent.parent))
import securicad.enterprise

if TYPE_CHECKING:
    from securicad.enterprise import AccessLevel, Client, Organization, Project, User
    from securicad.enterprise.exceptions import StatusCodeException

# isort: on


def get_url(endpoint: str) -> str:
    if conftest.BACKEND_URL is None:
        backend_url = conftest.BASE_URL
    else:
        backend_url = conftest.BACKEND_URL
    backend_url = urljoin(backend_url, "/api/v1/")
    return urljoin(backend_url, endpoint)


def get_client(username: str, password: str) -> "Client":
    return securicad.enterprise.client(
        base_url=conftest.BASE_URL,
        backend_url=conftest.BACKEND_URL,
        username=username,
        password=password,
        cacert=False,
    )


def get_client_org(
    username: str, password: str, organization: Optional[str]
) -> "Client":
    return securicad.enterprise.client(
        base_url=conftest.BASE_URL,
        backend_url=conftest.BACKEND_URL,
        username=username,
        password=password,
        organization=organization,
        cacert=False,
    )


def get_client_sysadmin() -> "Client":
    return get_client(conftest.ADMIN_USERNAME, conftest.ADMIN_PASSWORD)


def assert_access_token(client: "Client") -> None:
    assert client._get_access_token() is not None, "Missing access token in client"


def assert_not_access_token(client: "Client") -> None:
    assert client._get_access_token() is None, "Unexpected access token in client"


def assert_status_code_exception(
    exception: "StatusCodeException", status_code: int, method: str, url: str, data: Any
) -> None:
    assert (
        exception.status_code == status_code
    ), f"Unexpected status code {exception.status_code} != {status_code}"
    assert (
        exception.method == method
    ), f'Unexpected method "{exception.method}" != "{method}"'
    assert exception.url == url, f'Unexpected url "{exception.url}" != "{url}"'
    content = json.dumps(data, indent=2)
    assert (
        exception.content == content
    ), f"Invalid data\nExpected:\n{content}\nActual:\n{exception.content}"


def assert_org_data(org: "Organization", org_data: Dict[str, Any]) -> None:
    assert (
        org.tag == org_data["tag"]
    ), f"Unexpected organization tag \"{org.tag}\" != \"{org_data['tag']}\""
    assert (
        org.name == org_data["name"]
    ), f"Unexpected organization name \"{org.name}\" != \"{org_data['name']}\""


def assert_user_data(
    user: "User", user_data: Dict[str, Any], org: Optional[str] = None
) -> None:
    assert (
        user.uid == user_data["uid"]
    ), f"Unexpected user uid {user.uid} != {user_data['uid']}"
    assert (
        user.username == user_data["username"]
    ), f"Unexpected user username \"{user.username}\" != \"{user_data['username']}\""
    assert (
        user.firstname == user_data["firstname"]
    ), f"Unexpected user firstname \"{user.firstname}\" != \"{user_data['firstname']}\""
    assert (
        user.lastname == user_data["lastname"]
    ), f"Unexpected user lastname \"{user.lastname}\" != \"{user_data['lastname']}\""
    assert (
        user.role == user_data["role"]
    ), f"Unexpected user role \"{str(user.role)}\" != \"{str(user_data['role'])}\""
    if org is not None:
        assert (
            user.organization == org
        ), f'Unexpected user organization "{user.organization}" != "{org}"'


def assert_project_data(
    project: "Project", project_data: Dict[str, Any], access_level: "AccessLevel"
) -> None:
    assert (
        project.pid == project_data["pid"]
    ), f"Unexpected project pid \"{project.pid}\" != \"{project_data['pid']}\""
    assert (
        project.name == project_data["name"]
    ), f"Unexpected project name \"{project.name}\" != \"{project_data['name']}\""
    expected_description = (
        "" if project_data["description"] is None else project_data["description"]
    )
    assert (
        project.description == expected_description
    ), f'Unexpected project description "{project.description}" != "{expected_description}"'
    assert (
        project.access_level == access_level
    ), f'Unexpected project access level "{str(project.access_level)}" != "{str(access_level)}"'
