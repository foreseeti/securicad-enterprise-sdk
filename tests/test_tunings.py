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
from pathlib import Path

import pytest

import utils

# isort: off

sys.path.append(str(Path(__file__).resolve().parent.parent))
from securicad.enterprise.exceptions import StatusCodeException

from securicad.enterprise.tunings import Tunings

# isort: on


def get_converted(project, model, newformat):
    return Tunings._convert_to_old_format(
        project,
        model,
        op=newformat["op"],
        filterdict=newformat["filter"],
        tuning_type=newformat["type"],
        name="converted",
        ttc=newformat.get("ttc", None),
        tags=newformat.get("tags", []),
        consequence=newformat.get("consequence", None),
        probability=newformat.get("probability", None),
    )


@pytest.fixture()
def client():
    return utils.get_client_sysadmin()


@pytest.fixture()
def project(data, client):
    org = client.organizations.list_organizations()[0]
    return org.list_projects()[0]


@pytest.fixture()
def model(data, project, client):
    import io

    with open("acme.sCAD", "rb") as reader:
        data = io.BytesIO(reader.read())

    model = client.models.upload_scad_model(
        project, filename="acme.sCAD", file_io=data, description=""
    )
    yield model.get_model()
    model.delete()


def test_convert_attacker_object_name(data, project, model):
    newformat = {
        "type": "attacker",
        "op": "apply",
        "filter": {"attackstep": "DevelopZeroDay", "object_name": "Prod srv 1"},
    }
    oldformat: Dict[str, Any] = {
        "pid": project.pid,
        "configs": [
            {
                "attackstep": "developZeroDay",
                "condition": {"tag": "", "value": ""},
                "consequence": None,
                "defense": None,
                "id": 90,
                "name": "Prod srv 1",
                "probability": None,
                "scope": "object",
                "ttc": None,
            }
        ],
    }
    converted = get_converted(project, model, newformat)
    assert converted == oldformat


def test_convert_attacker_metaconcept(data, project, model):
    newformat = {
        "type": "attacker",
        "op": "apply",
        "filter": {"attackstep": "DevelopZeroDay", "metaconcept": "Host"},
    }
    oldformat: Dict[str, Any] = {
        "pid": project.pid,
        "configs": [
            {
                "attackstep": "developZeroDay",
                "condition": {"tag": "", "value": ""},
                "consequence": None,
                "defense": None,
                "id": "Host",
                "probability": None,
                "scope": "class",
                "ttc": None,
            }
        ],
    }
    converted = get_converted(project, model, newformat)
    assert converted == oldformat


def test_convert_attacker_metaconcept_tag(data, project, model):
    newformat = {
        "type": "attacker",
        "op": "apply",
        "filter": {
            "attackstep": "DevelopZeroDay",
            "metaconcept": "Host",
            "tags": {"tagkey": "tagvalue"},
        },
    }
    oldformat: Dict[str, Any] = {
        "pid": project.pid,
        "configs": [
            {
                "attackstep": "developZeroDay",
                "condition": {"tag": "tagkey", "value": "tagvalue"},
                "consequence": None,
                "defense": None,
                "id": "Host",
                "probability": None,
                "scope": "class",
                "ttc": None,
            }
        ],
    }
    converted = get_converted(project, model, newformat)
    assert converted == oldformat


def test_convert_ttc_metaconcept(data, project, model):
    newformat = {
        "type": "ttc",
        "op": "apply",
        "filter": {"attackstep": "DevelopZeroDay", "metaconcept": "Host"},
        "ttc": "Exponential,3",
    }
    oldformat: Dict[str, Any] = {
        "pid": project.pid,
        "configs": [
            {
                "attackstep": "developZeroDay",
                "condition": {"tag": "", "value": ""},
                "consequence": None,
                "defense": None,
                "id": "Host",
                "probability": None,
                "scope": "class",
                "ttc": "Exponential,3",
            }
        ],
    }
    converted = get_converted(project, model, newformat)
    assert converted == oldformat


def test_convert_ttc_object(data, project, model):
    newformat = {
        "type": "ttc",
        "op": "apply",
        "filter": {"attackstep": "DevelopZeroDay", "object_name": "Prod srv 1"},
        "ttc": "Exponential,3",
    }
    oldformat: Dict[str, Any] = {
        "pid": project.pid,
        "configs": [
            {
                "attackstep": "developZeroDay",
                "condition": {"tag": "", "value": ""},
                "consequence": None,
                "defense": None,
                "id": 90,
                "name": "Prod srv 1",
                "probability": None,
                "scope": "object",
                "ttc": "Exponential,3",
            }
        ],
    }
    converted = get_converted(project, model, newformat)
    assert converted == oldformat


def verify_tuning_response(
    tuning_data,
    pid,
    id_=None,
    scope="",
    attackstep=None,
    ttc="",
    condition={"tag": "", "value": ""},
    consequence=None,
    defense=None,
    probability=None,
    class_=None,
    name=None,
    tag=None,
    value=None,
):
    assert tuning_data.pid == pid
    assert tuning_data.id_ == id_
    assert tuning_data.scope == scope
    assert tuning_data.attackstep == attackstep
    assert tuning_data.ttc == ttc
    assert tuning_data.condition == condition
    assert tuning_data.consequence == consequence
    assert tuning_data.defense == defense
    assert tuning_data.probability == probability
    assert tuning_data.class_ == class_
    assert tuning_data.name == name
    assert tuning_data.tag == tag
    assert tuning_data.value == value


# Attacker entry


def test_attacker_object_name(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="attacker",
        op="apply",
        filterdict={"attackstep": "DevelopZeroDay", "object_name": "Prod srv 1"},
        name="test_attacker_object_name",
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        attackstep="developZeroDay",
        scope="object",
        name="Prod srv 1",
        id_=90,
    )


def test_attacker_object_tag(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="attacker",
        op="apply",
        filterdict={"attackstep": "DevelopZeroDay", "tags": {"env": "prod"}},
        name="test_attacker_object_name",
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        attackstep="developZeroDay",
        scope="any",
        condition={"tag": "env", "value": "prod"},
    )


# TTC all attacksteps


def test_all_attackstep_ttc_all(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={},
        name="test_all_attackstep_ttc_all",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning, pid=project.pid, scope="any", attackstep="", ttc="Exponential,3"
    )


def test_all_attackstep_ttc_all_tag(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"tags": {"env": "prod"}},
        name="test_all_attackstep_ttc_all",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        scope="any",
        attackstep="",
        ttc="Exponential,3",
        condition={"tag": "env", "value": "prod"},
    )


def test_all_attackstep_ttc_class(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"metaconcept": "Host"},
        name="test_all_attackstep_ttc_class",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        scope="class",
        id_="Host",
        ttc="Exponential,3",
        attackstep="",
    )


def test_all_attackstep_ttc_class_tag(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"metaconcept": "Host", "tags": {"env": "prod"}},
        name="test_all_attackstep_ttc_class",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        scope="class",
        id_="Host",
        ttc="Exponential,3",
        attackstep="",
        condition={"tag": "env", "value": "prod"},
    )


def test_all_attackstep_ttc_object(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"metaconcept": "Host", "object_name": "Prod srv 1"},
        name="test_all_attackstep_ttc_object",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        scope="object",
        name="Prod srv 1",
        class_="Host",
        ttc="Exponential,3",
        id_=90,
        attackstep="",
    )


# TTC one attackstep


def test_one_attackstep_ttc(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"attackstep": "DevelopZeroDay"},
        name="test_one_attackstep_ttc_class",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        scope="any",
        ttc="Exponential,3",
        attackstep="developZeroDay",
    )


def test_one_attackstep_ttc_tag(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"attackstep": "DevelopZeroDay", "tags": {"env": "prod"}},
        name="test_one_attackstep_ttc_class",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        scope="any",
        ttc="Exponential,3",
        attackstep="developZeroDay",
        condition={"tag": "env", "value": "prod"},
    )


def test_one_attackstep_ttc_class(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"metaconcept": "Host", "attackstep": "DevelopZeroDay"},
        name="test_one_attackstep_ttc_class",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        scope="class",
        id_="Host",
        ttc="Exponential,3",
        attackstep="developZeroDay",
    )


def test_one_attackstep_ttc_class_tag(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={
            "metaconcept": "Host",
            "attackstep": "DevelopZeroDay",
            "tags": {"env": "prod"},
        },
        name="test_one_attackstep_ttc_class",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        scope="class",
        id_="Host",
        ttc="Exponential,3",
        attackstep="developZeroDay",
        condition={"tag": "env", "value": "prod"},
    )


def test_one_attackstep_ttc_object(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"object_name": "Prod srv 1", "attackstep": "DevelopZeroDay"},
        name="test_one_attackstep_ttc_object",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        scope="object",
        name="Prod srv 1",
        ttc="Exponential,3",
        id_=90,
        attackstep="developZeroDay",
    )


def test_one_attackstep_ttc_object(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={
            "metaconcept": "Host",
            "object_name": "Prod srv 1",
            "attackstep": "DevelopZeroDay",
        },
        name="test_one_attackstep_ttc_object",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        scope="object",
        name="Prod srv 1",
        class_="Host",
        ttc="Exponential,3",
        id_=90,
        attackstep="developZeroDay",
    )


# Defense probability


def test_defense_probability_all(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={},
        name="test_defense_probability_all",
        probability="0.5",
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        scope="any",
        attackstep="",
        probability="0.5",
    )


def test_defense_probability_all_tag(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"metaconcept": "Host", "tags": {"env": "prod"}},
        name="test_defense_probability_class",
        probability="0.5",
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        id_="Host",
        scope="class",
        attackstep="",
        probability="0.5",
        condition={"tag": "env", "value": "prod"},
    )


def test_defense_probability_class(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"metaconcept": "Host"},
        name="test_defense_probability_class",
        probability="0.5",
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        id_="Host",
        scope="class",
        probability="0.5",
        attackstep="",
    )


def test_defense_probability_class_tag(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"metaconcept": "Host", "tags": {"env": "prod"}},
        name="test_defense_probability_class",
        probability="0.5",
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        id_="Host",
        scope="class",
        probability="0.5",
        attackstep="",
        condition={"tag": "env", "value": "prod"},
    )


def test_defense_probability_object(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"object_name": "Prod srv 1"},
        name="test_defense_probability_class",
        probability="0.5",
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        name="Prod srv 1",
        scope="object",
        probability="0.5",
        attackstep="",
        id_=90,
    )


def test_defense_probability_class_object(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"metaconcept": "Host", "object_name": "Prod srv 1"},
        name="test_defense_probability_class",
        probability="0.5",
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        class_="Host",
        name="Prod srv 1",
        scope="object",
        probability="0.5",
        attackstep="",
        id_=90,
    )


# Set tags


def test_tag_all(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="tags",
        op="apply",
        filterdict={},
        name="test_defense_probability_class",
        tags={"a": "b"},
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        scope="any",
        attackstep="",
        tag="a",
        value="b",
    )


def test_tag_all_tag(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="tags",
        op="apply",
        filterdict={"tags": {"env": "prod"}},
        name="test_defense_probability_class",
        tags={"a": "b"},
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        scope="any",
        attackstep="",
        tag="a",
        value="b",
        condition={"tag": "env", "value": "prod"},
    )


def test_tag_class(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="tags",
        op="apply",
        filterdict={"metaconcept": "Host"},
        name="test_defense_probability_class",
        tags={"a": "b"},
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        id_="Host",
        scope="class",
        attackstep="",
        tag="a",
        value="b",
    )


def test_tag_class_tag(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="tags",
        op="apply",
        filterdict={"metaconcept": "Host", "tags": {"env": "prod"}},
        name="test_defense_probability_class",
        tags={"a": "b"},
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        id_="Host",
        scope="class",
        attackstep="",
        tag="a",
        value="b",
        condition={"tag": "env", "value": "prod"},
    )


def test_tag_object(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="tags",
        op="apply",
        filterdict={"object_name": "Prod srv 1"},
        name="test_defense_probability_object",
        tags={"a": "b"},
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        name="Prod srv 1",
        id_=90,
        scope="object",
        attackstep="",
        tag="a",
        value="b",
    )


def test_tag_object_class(client, data, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="tags",
        op="apply",
        filterdict={"metaconcept": "Host", "object_name": "Prod srv 1"},
        name="test_defense_probability_object_class",
        tags={"a": "b"},
    )
    verify_tuning_response(
        tuning,
        pid=project.pid,
        class_="Host",
        id_=90,
        name="Prod srv 1",
        scope="object",
        attackstep="",
        tag="a",
        value="b",
    )
