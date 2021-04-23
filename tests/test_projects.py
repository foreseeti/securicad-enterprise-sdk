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

import sys
import uuid
from pathlib import Path

import pytest

import utils

# isort: off

sys.path.append(str(Path(__file__).resolve().parent.parent))
from securicad.enterprise.exceptions import StatusCodeException

from securicad.enterprise.projects import AccessLevel
from securicad.enterprise.users import Role

# isort: on


def test_list_projects(data, client):
    assert len(client.projects.list_projects()) == len(
        data["organizations"]["org1"]["projects"]
    )


def test_get_project_by_pid(data, client):
    for org_data in data["organizations"].values():
        for project_data in org_data["projects"].values():
            proj = client.projects.get_project_by_pid(project_data["pid"])
            assert proj.pid == project_data["pid"]
            assert proj.name == project_data["name"]


def test_get_project_by_name(data, client):
    for org_data in data["organizations"].values():
        for project_data in org_data["projects"].values():
            proj = client.projects.get_project_by_name(project_data["name"])
            assert proj.pid == project_data["pid"]
            assert proj.name == project_data["name"]


def test_create_project(client, organization):
    name = str(uuid.uuid4())
    description = str(uuid.uuid4())
    proj = client.projects.create_project(
        name=name, description=description, organization=organization
    )
    assert proj.name == name
    assert proj.description == description
    proj.delete()


def test_project_update(client, project):
    name = str(uuid.uuid4())
    description = str(uuid.uuid4())
    project.update(name=name, description=description)
    project2 = client.projects.get_project_by_name(name=name)

    assert project.name == name
    assert project.description == description

    assert project2.pid == project.pid
    assert project2.name == name
    assert project2.description == description


def test_project_delete(client, organization):
    assert len(client.projects.list_projects()) == 1
    name = str(uuid.uuid4())
    description = str(uuid.uuid4())
    proj = client.projects.create_project(
        name=name, description=description, organization=organization
    )
    assert len(client.projects.list_projects()) == 2
    proj.delete()
    assert len(client.projects.list_projects()) == 1


def test_project_list_users(project):
    users = project.list_users()
    assert len(users) == 1


def test_project_add_user(client, organization):
    user = client.users.create_user(
        username="user",
        password="psw",
        firstname="f",
        lastname="l",
        role=Role.USER,
        organization=organization,
    )
    proj = client.projects.create_project(
        name=str(uuid.uuid4()), description=str(uuid.uuid4()), organization=organization
    )
    assert len(proj.list_users()) == 1
    proj.add_user(user, AccessLevel.ADMIN)
    assert len(proj.list_users()) == 2
    user.delete()
    proj.delete()


def test_project_remove_user(client, organization):
    user = client.users.create_user(
        username="user",
        password="psw",
        firstname="f",
        lastname="l",
        role=Role.USER,
        organization=organization,
    )
    proj = client.projects.create_project(
        name=str(uuid.uuid4()), description=str(uuid.uuid4()), organization=organization
    )
    assert len(proj.list_users()) == 1
    proj.add_user(user, AccessLevel.ADMIN)
    user.delete()
    assert len(proj.list_users()) == 1
    proj.delete()


def test_project_get_access_level(client, organization):
    proj = client.projects.create_project(
        name=str(uuid.uuid4()), description=str(uuid.uuid4()), organization=organization
    )
    for level in AccessLevel:
        user = client.users.create_user(
            username="user",
            password="psw",
            firstname="f",
            lastname="l",
            role=Role.USER,
            organization=organization,
        )
        proj.add_user(user, level)
        assert proj.get_access_level(user) == level
        user.delete()
    proj.delete()


def test_project_set_access_level(client, organization):
    user = client.users.create_user(
        username="user",
        password="psw",
        firstname="f",
        lastname="l",
        role=Role.USER,
        organization=organization,
    )
    proj = client.projects.create_project(
        name=str(uuid.uuid4()), description=str(uuid.uuid4()), organization=organization
    )
    levels = list(AccessLevel)
    for lidx, level in enumerate(levels):
        proj.add_user(user, level)
        assert proj.get_access_level(user) == level
        next_level = levels[(lidx + 1) % len(levels)]
        proj.set_access_level(user, next_level)
        assert proj.get_access_level(user) == next_level
        proj.remove_user(user)
    user.delete()
    proj.delete()


def test_list_models(project):
    assert project.list_models() == []
    modelpath = Path(__file__).with_name("aws.sCAD")
    with open(modelpath, mode="rb") as reader:
        project.upload_scad_model(
            filename="aws.sCAD", file_io=reader, description="descr"
        )
    fetched = project.list_models()
    assert len(fetched) == 1
    fetched_model = fetched[0]
    assert fetched_model.name == "aws"
    assert fetched_model.description == "descr"
    fetched_model.delete()
    assert project.list_models() == []


def test_project_import_models(client, organization, project):
    other_project = client.projects.create_project(
        name=str(uuid.uuid4()), description=str(uuid.uuid4()), organization=organization
    )
    modelpath = Path(__file__).with_name("aws.sCAD")
    with open(modelpath, mode="rb") as reader:
        model_info = other_project.upload_scad_model(
            filename="aws.sCAD", file_io=reader, description="descr"
        )
    assert project.list_models() == []
    project.import_models([model_info])
    assert len(project.list_models()) == 1
    other_project.delete()


def test_project_list_scenarios(project):
    modelpath = Path(__file__).with_name("aws.sCAD")
    with open(modelpath, mode="rb") as reader:
        model_info = project.upload_scad_model(
            filename="aws.sCAD", file_io=reader, description="descr"
        )
    assert project.list_scenarios() == []
    project.create_scenario(
        model_info=model_info,
        name="simulation",
        description="descr",
        tunings=[],
    )
    assert len(project.list_scenarios()) == 1


# TODO
# Tests not running as sysadmin.
# Negative tests.
# - Attempted project access
# - Attempted project creation
# - Attempted project delete
