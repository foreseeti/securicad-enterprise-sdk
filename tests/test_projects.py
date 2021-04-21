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

import random
import sys
import uuid
from pathlib import Path

import pytest

import utils

# isort: off

sys.path.append(str(Path(__file__).resolve().parent.parent))
from securicad.enterprise.exceptions import StatusCodeException

from securicad.enterprise.projects import AccessLevel
from securicad.enterprise.users import User, Role

# isort: on


def test_list_projects(data, client):
    assert len(client.projects.list_projects()) == 1


def test_get_project_by_pid(data, client):
    data_pid = data["organizations"]["org1"]["projects"]["p1"]["pid"]
    p = client.projects.get_project_by_pid(pid=data_pid)
    assert p.pid == data_pid


def test_get_project_by_name(data, client):
    data_name = data["organizations"]["org1"]["projects"]["p1"]["name"]
    p = client.projects.get_project_by_name(name=data_name)
    assert p.name == data_name


def test_create_project(data, client, organization):
    name = str(uuid.uuid4())
    description = str(uuid.uuid4())
    p = client.projects.create_project(
        name=name, description=description, organization=organization
    )
    assert p.name == name
    assert p.description == description
    p.delete()


def test_project_update(data, client, project, organization):
    name = str(uuid.uuid4())
    description = str(uuid.uuid4())
    project.update(name=name, description=description)
    p2 = client.projects.get_project_by_name(name=name)
    assert p2.pid == project.pid
    assert p2.name == name
    assert p2.description == description


def test_project_delete(data, client, organization):
    assert len(client.projects.list_projects()) == 1
    name = str(uuid.uuid4())
    description = str(uuid.uuid4())
    p = client.projects.create_project(
        name=name, description=description, organization=organization
    )
    assert len(client.projects.list_projects()) == 2
    p.delete()
    assert len(client.projects.list_projects()) == 1


def test_project_list_users(data, client, project):
    users = project.list_users()
    assert len(users) == 1


def test_project_add_remove_user_and_get_access_level(data, client, organization):
    user = client.users.create_user(
        username="user",
        password="psw",
        firstname="f",
        lastname="l",
        role=Role.USER,
        organization=organization,
    )
    p = client.projects.create_project(
        name=str(uuid.uuid4()), description=str(uuid.uuid4()), organization=organization
    )
    for level in [
        AccessLevel.GUEST,
        AccessLevel.USER,
        AccessLevel.OWNER,
        AccessLevel.ADMIN,
    ]:
        p.add_user(user, level)
        assert p.get_access_level(user) == level
        assert len(p.list_users()) == 2, [
            p.username for p in p.list_users()
        ]  # admin, and one already existed
        p.remove_user(user)
    user.delete()
    p.delete()


def test_project_set_access_level(data, client, organization):
    user = client.users.create_user(
        username="user",
        password="psw",
        firstname="f",
        lastname="l",
        role=Role.USER,
        organization=organization,
    )
    p = client.projects.create_project(
        name=str(uuid.uuid4()), description=str(uuid.uuid4()), organization=organization
    )
    levels = [AccessLevel.GUEST, AccessLevel.USER, AccessLevel.OWNER, AccessLevel.ADMIN]
    for lidx, level in enumerate(levels):
        p.add_user(user, level)
        assert p.get_access_level(user) == level
        next_level = levels[(lidx + 1) % len(levels)]
        p.set_access_level(user, next_level)
        assert p.get_access_level(user) == next_level
        p.remove_user(user)
    user.delete()
    p.delete()


def test_list_models(data, client, project):
    assert project.list_models() == []
    modelpath = Path(__file__).with_name("aws.sCAD")
    model_info = project.upload_scad_model(
        filename="aws.sCAD", file_io=open(modelpath, mode="rb"), description="descr"
    )
    fetched = project.list_models()
    assert len(fetched) == 1
    fetched_model = fetched[0]
    assert fetched_model.name == "aws"
    assert fetched_model.description == "descr"
    fetched_model.delete()
    assert project.list_models() == []


def test_project_import_models(data, client, organization, project):
    other_project = client.projects.create_project(
        name=str(uuid.uuid4()), description=str(uuid.uuid4()), organization=organization
    )
    modelpath = Path(__file__).with_name("aws.sCAD")
    model_info = other_project.upload_scad_model(
        filename="aws.sCAD", file_io=open(modelpath, mode="rb"), description="descr"
    )
    assert project.list_models() == []
    project.import_models([model_info])
    assert len(project.list_models()) == 1
    other_project.delete()


def test_project_list_scenarios(data, client, project):
    modelpath = Path(__file__).with_name("aws.sCAD")
    model_info = project.upload_scad_model(
        filename="aws.sCAD", file_io=open(modelpath, mode="rb"), description="descr"
    )
    assert project.list_scenarios() == []
    scenario = client.scenarios.create_scenario(
        project=project,
        model_info=model_info,
        name="simulation",
        description="descr",
        tunings=[],
    )
    assert len(project.list_scenarios()) == 1
