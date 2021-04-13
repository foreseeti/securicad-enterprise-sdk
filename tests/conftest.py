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
from typing import Any, Dict, List, Optional

import jsonschema
import pytest

# isort: off

sys.path.append(str(Path(__file__).resolve().parent.parent))
from securicad.enterprise import Role

# isort: on

DATA: Dict[str, Dict[str, Any]] = {"users": {}, "organizations": {}}

BASE_URL: Optional[str] = None
BACKEND_URL: Optional[str] = None
ADMIN_USERNAME: Optional[str] = None
ADMIN_PASSWORD: Optional[str] = None
COMMON_PASSWORD: Optional[str] = None
AWS_IMPORT_CONFIG: Optional[Dict[str, Any]] = None

AWSLANG: Optional[List[Dict[str, Any]]] = None


def get_config() -> Dict[str, Any]:
    schema_path = Path(__file__).with_name("config.schema.json")
    with schema_path.open(mode="r", encoding="utf-8") as f:
        schema = json.load(f)
    config_path = Path(__file__).with_name("config.json")
    with config_path.open(mode="r", encoding="utf-8") as f:
        config = json.load(f)
    jsonschema.validate(instance=config, schema=schema)
    return config


def get_data() -> Dict[str, Any]:
    schema_path = Path(__file__).with_name("data.schema.json")
    with schema_path.open(mode="r", encoding="utf-8") as f:
        schema = json.load(f)
    data_path = Path(__file__).with_name("data.json")
    with data_path.open(mode="r", encoding="utf-8") as f:
        data = json.load(f)
    jsonschema.validate(instance=data, schema=schema)
    return data


def get_awslang() -> List[Dict[str, Any]]:
    awslang_path = Path(__file__).with_name("awslang.json")
    with awslang_path.open(mode="r", encoding="utf-8") as f:
        awslang = json.load(f)
    return awslang


def read_config() -> None:
    global BASE_URL, BACKEND_URL, ADMIN_USERNAME, ADMIN_PASSWORD, COMMON_PASSWORD, AWS_IMPORT_CONFIG
    config = get_config()
    BASE_URL = config["base_url"]
    BACKEND_URL = config["backend_url"]
    ADMIN_USERNAME = config["admin_username"]
    ADMIN_PASSWORD = config["admin_password"]
    COMMON_PASSWORD = config["common_password"]
    AWS_IMPORT_CONFIG = config["aws_import_config"]
    assert BASE_URL, "base_url is not set in config.json"
    assert ADMIN_USERNAME, "admin_username is not set in config.json"
    assert ADMIN_PASSWORD, "admin_password is not set in config.json"
    assert COMMON_PASSWORD, "common_password is not set in config.json"
    assert AWS_IMPORT_CONFIG["accounts"], "accounts is not set in config.json"
    for account in AWS_IMPORT_CONFIG["accounts"]:
        assert account["access_key"], "access_key is not set in config.json"
        assert account["secret_key"], "secret_key is not set in config.json"
        assert account["regions"], "regions is not set in config.json"
        for region in account["regions"]:
            assert region, "region is not set in config.json"


def read_data() -> None:
    def get_user(user: Dict[str, Any]) -> Dict[str, Any]:
        if user["password"] is None:
            password = COMMON_PASSWORD
        else:
            password = user["password"]
        return {
            "username": user["username"],
            "password": password,
            "firstname": user["firstname"],
            "lastname": user["lastname"],
            "role": Role[user["role"]],
        }

    def get_org(org: Dict[str, Any]) -> Dict[str, Any]:
        users = {u["username"]: get_user(u) for u in org["users"]}
        projects = {p["name"]: get_project(p) for p in org["projects"]}
        return {
            "name": org["name"],
            "users": users,
            "projects": projects,
        }

    def get_project(project: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "name": project["name"],
            "description": project["description"],
        }

    data = get_data()
    DATA["users"][ADMIN_USERNAME] = {
        "uid": 1,
        "username": ADMIN_USERNAME,
        "password": ADMIN_PASSWORD,
        "firstname": "sys",
        "lastname": "admin",
        "role": Role.SYSADMIN,
    }
    for user in data["users"]:
        DATA["users"][user["username"]] = get_user(user)
    for org in data["organizations"]:
        DATA["organizations"][org["name"]] = get_org(org)


def create_data() -> None:
    import utils

    client = utils.get_client_sysadmin()

    # Delete organizations
    for org in client.organizations.list_organizations():
        org.delete()

    # Delete users except sysadmin
    for user in client.users.list_users():
        if user.username != ADMIN_USERNAME:
            user.delete()

    # Create other sysadmins
    for user_data in DATA["users"].values():
        if user_data["username"] != ADMIN_USERNAME:
            user = client.users.create_user(
                username=user_data["username"],
                password=user_data["password"],
                firstname=user_data["firstname"],
                lastname=user_data["lastname"],
                role=user_data["role"],
            )
            user_data["uid"] = user.uid

    # Create organizations
    for org_data in DATA["organizations"].values():
        org = client.organizations.create_organization(name=org_data["name"])
        org_data["tag"] = org.tag

        # Create organization users
        for user_data in org_data["users"].values():
            user = client.users.create_user(
                username=user_data["username"],
                password=user_data["password"],
                firstname=user_data["firstname"],
                lastname=user_data["lastname"],
                role=user_data["role"],
                organization=org,
            )
            user_data["uid"] = user.uid

        # Create organization projects
        for project_data in org_data["projects"].values():
            project = client.projects.create_project(
                name=project_data["name"],
                description=project_data["description"],
                organization=org,
            )
            project_data["pid"] = project.pid

    client.logout()


@pytest.fixture(scope="session", autouse=True)
def init_data() -> None:
    read_config()
    read_data()
    create_data()


@pytest.fixture
def data() -> Dict[str, Dict[str, Any]]:
    return DATA


@pytest.fixture
def awslang() -> List[Dict[str, Any]]:
    global AWSLANG
    if AWSLANG is None:
        AWSLANG = get_awslang()
    return AWSLANG


@pytest.fixture()
def client():
    import utils

    return utils.get_client_sysadmin()


@pytest.fixture()
def project(data, client):
    org = client.organizations.list_organizations()[0]
    project = client.projects.create_project(
        name="project", description="", organization=org
    )
    yield project
    project.delete()


@pytest.fixture()
def model(data, project, client):
    name = "smallAwsModel.sCAD"
    model_path = Path(__file__).with_name(name)
    with model_path.open(mode="rb") as reader:
        model = client.models.upload_scad_model(
            project, filename=name, file_io=reader, description=""
        )
        yield model.get_model()

    model.delete()
