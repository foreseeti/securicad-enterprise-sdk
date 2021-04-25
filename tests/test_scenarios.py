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

# isort: on
def test_list_create_scenario(data, client, project):
    assert client.scenarios.list_scenarios(project) == []
    modelpath = Path(__file__).with_name("aws.sCAD")
    model_info = project.upload_scad_model(
        filename="aws.sCAD", file_io=open(modelpath, mode="rb"), description="descr"
    )
    name = str(uuid.uuid4())
    description = str(uuid.uuid4())
    scenario = client.scenarios.create_scenario(
        project=project,
        name=name,
        model_info=model_info,
        description=description,
        tunings=[],
    )
    fetched = client.scenarios.list_scenarios(project)
    assert len(fetched) == 1, fetched
    fetched_scenario = fetched[0]
    assert fetched_scenario.name == name
    assert fetched_scenario.description == description


# TODO:
def test_get_scenario_by_tid(data, client, project):
    modelpath = Path(__file__).with_name("aws.sCAD")
    model_info = project.upload_scad_model(
        filename="aws.sCAD", file_io=open(modelpath, mode="rb"), description="descr"
    )
    name = str(uuid.uuid4())
    description = str(uuid.uuid4())
    scenario = client.scenarios.create_scenario(
        project=project,
        name=name,
        model_info=model_info,
        description=description,
        tunings=[],
    )
    fetched = client.scenarios.get_scenario_by_tid(project=project, tid=scenario.tid)
    assert scenario.tid == fetched.tid
    assert fetched.name == name
    assert fetched.description == description


def test_get_scenario_by_name(data, client, project):
    modelpath = Path(__file__).with_name("aws.sCAD")
    model_info = project.upload_scad_model(
        filename="aws.sCAD", file_io=open(modelpath, mode="rb"), description="descr"
    )
    name = str(uuid.uuid4())
    description = str(uuid.uuid4())
    scenario = client.scenarios.create_scenario(
        project=project,
        name=name,
        model_info=model_info,
        description=description,
        tunings=[],
    )
    fetched = client.scenarios.get_scenario_by_name(project=project, name=name)
    assert scenario.tid == fetched.tid
    assert fetched.name == name
    assert fetched.description == description


def test_scenario_update(data, client, project):
    modelpath = Path(__file__).with_name("aws.sCAD")
    model_info = project.upload_scad_model(
        filename="aws.sCAD", file_io=open(modelpath, mode="rb"), description="descr"
    )
    name = str(uuid.uuid4())
    description = str(uuid.uuid4())
    scenario = client.scenarios.create_scenario(
        project=project,
        name=name,
        model_info=model_info,
        description=description,
        tunings=[],
    )
    new_name = str(uuid.uuid4())
    new_description = str(uuid.uuid4())
    scenario.update(name=new_name, description=new_description)
    fetched = client.scenarios.get_scenario_by_name(project=project, name=new_name)
    assert scenario.tid == fetched.tid
    assert fetched.name == new_name
    assert fetched.description == new_description


def test_delete_scenario(data, client, project):
    assert client.scenarios.list_scenarios(project) == []
    modelpath = Path(__file__).with_name("aws.sCAD")
    model_info = project.upload_scad_model(
        filename="aws.sCAD", file_io=open(modelpath, mode="rb"), description="descr"
    )
    name = str(uuid.uuid4())
    description = str(uuid.uuid4())
    scenario = client.scenarios.create_scenario(
        project=project,
        name=name,
        model_info=model_info,
        description=description,
        tunings=[],
    )
    fetched = client.scenarios.list_scenarios(project)
    fetched_scenario = fetched[0]
    scenario.delete()
    assert client.scenarios.list_scenarios(project) == []
    try:
        fetched_scenario.delete()
        assert False, "double delete should throw exception"
    except:
        pass


def test_scenario_list_simulations(data, client, project):
    assert client.scenarios.list_scenarios(project) == []
    modelpath = Path(__file__).with_name("aws.sCAD")
    model_info = project.upload_scad_model(
        filename="aws.sCAD", file_io=open(modelpath, mode="rb"), description="descr"
    )
    name = str(uuid.uuid4())
    description = str(uuid.uuid4())
    scenario = client.scenarios.create_scenario(
        project=project,
        name=name,
        model_info=model_info,
        description=description,
        tunings=[],
    )
    fetched = scenario.list_simulations()
    assert len(fetched) == 1, fetched
    fetched_simulation = fetched[0]
    assert fetched_simulation.name == "Initial simulation"
