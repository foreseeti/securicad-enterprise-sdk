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


def test_convert_attacker_object_name(data, project, model):
    newformat = {
        "type": "attacker",
        "op": "apply",
        "filter": {"attackstep": "HighPrivilegeAccess", "object_name": "i-1"},
    }
    oldformat: Dict[str, Any] = {
        "pid": project.pid,
        "configs": [
            {
                "attackstep": "highPrivilegeAccess",
                "condition": {"tag": "", "value": ""},
                "consequence": None,
                "defense": None,
                "id": 151,
                "name": "i-1",
                "probability": None,
                "scope": "object",
            }
        ],
    }
    converted = get_converted(project, model, newformat)
    assert converted == oldformat


def test_convert_attacker_metaconcept(data, project, model):
    newformat = {
        "type": "attacker",
        "op": "apply",
        "filter": {"attackstep": "HighPrivilegeAccess", "metaconcept": "EC2Instance"},
    }
    oldformat: Dict[str, Any] = {
        "pid": project.pid,
        "configs": [
            {
                "attackstep": "highPrivilegeAccess",
                "condition": {"tag": "", "value": ""},
                "consequence": None,
                "defense": None,
                "id": "EC2Instance",
                "probability": None,
                "scope": "class",
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
            "attackstep": "HighPrivilegeAccess",
            "metaconcept": "EC2Instance",
            "tags": {"tagkey": "tagvalue"},
        },
    }
    oldformat: Dict[str, Any] = {
        "pid": project.pid,
        "configs": [
            {
                "attackstep": "highPrivilegeAccess",
                "condition": {"tag": "tagkey", "value": "tagvalue"},
                "consequence": None,
                "defense": None,
                "id": "EC2Instance",
                "probability": None,
                "scope": "class",
            }
        ],
    }
    converted = get_converted(project, model, newformat)
    assert converted == oldformat


def test_convert_ttc_metaconcept(data, project, model):
    newformat = {
        "type": "ttc",
        "op": "apply",
        "filter": {"attackstep": "HighPrivilegeAccess", "metaconcept": "EC2Instance"},
        "ttc": "Exponential,3",
    }
    oldformat: Dict[str, Any] = {
        "pid": project.pid,
        "configs": [
            {
                "attackstep": "highPrivilegeAccess",
                "condition": {"tag": "", "value": ""},
                "consequence": None,
                "defense": None,
                "id": "EC2Instance",
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
        "filter": {"attackstep": "HighPrivilegeAccess", "object_name": "i-1"},
        "ttc": "Exponential,3",
    }
    oldformat: Dict[str, Any] = {
        "pid": project.pid,
        "configs": [
            {
                "attackstep": "highPrivilegeAccess",
                "condition": {"tag": "", "value": ""},
                "consequence": None,
                "defense": None,
                "id": 151,
                "name": "i-1",
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
    project,
    id_=None,
    scope="",
    attackstep=None,
    ttc=None,
    condition={"tag": "", "value": ""},
    consequence=None,
    defense=None,
    probability=None,
    class_=None,
    name=None,
    tag=None,
    value=None,
):
    assert tuning_data.project.pid == project.pid
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


def test_attacker_object_name(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="attacker",
        op="apply",
        filterdict={"attackstep": "HighPrivilegeAccess", "object_name": "i-1"},
        name="test_attacker_object_name",
    )
    verify_tuning_response(
        tuning,
        project=project,
        attackstep="highPrivilegeAccess",
        scope="object",
        name="i-1",
        id_=151,
    )


def test_attacker_object_tag(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="attacker",
        op="apply",
        filterdict={"attackstep": "HighPrivilegeAccess", "tags": {"env": "prod"}},
        name="test_attacker_object_name",
    )
    verify_tuning_response(
        tuning,
        project=project,
        attackstep="highPrivilegeAccess",
        scope="any",
        condition={"tag": "env", "value": "prod"},
    )


# TTC all attacksteps


def test_all_attackstep_ttc_all(client, project, model):
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
        tuning, project=project, scope="any", attackstep="", ttc="Exponential,3"
    )


def test_all_attackstep_ttc_all_tag(client, project, model):
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
        project=project,
        scope="any",
        attackstep="",
        ttc="Exponential,3",
        condition={"tag": "env", "value": "prod"},
    )


def test_all_attackstep_ttc_class(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"metaconcept": "EC2Instance"},
        name="test_all_attackstep_ttc_class",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning,
        project=project,
        scope="class",
        id_="EC2Instance",
        ttc="Exponential,3",
        attackstep="",
    )


def test_all_attackstep_ttc_class_tag(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"metaconcept": "EC2Instance", "tags": {"env": "prod"}},
        name="test_all_attackstep_ttc_class",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning,
        project=project,
        scope="class",
        id_="EC2Instance",
        ttc="Exponential,3",
        attackstep="",
        condition={"tag": "env", "value": "prod"},
    )


def test_all_attackstep_ttc_object(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"metaconcept": "EC2Instance", "object_name": "i-1"},
        name="test_all_attackstep_ttc_object",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning,
        project=project,
        scope="object",
        name="i-1",
        class_="EC2Instance",
        ttc="Exponential,3",
        id_=151,
        attackstep="",
    )


# TTC one attackstep


def test_one_attackstep_ttc(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"attackstep": "HighPrivilegeAccess"},
        name="test_one_attackstep_ttc_class",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning,
        project=project,
        scope="any",
        ttc="Exponential,3",
        attackstep="highPrivilegeAccess",
    )


def test_one_attackstep_ttc_tag(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"attackstep": "HighPrivilegeAccess", "tags": {"env": "prod"}},
        name="test_one_attackstep_ttc_class",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning,
        project=project,
        scope="any",
        ttc="Exponential,3",
        attackstep="highPrivilegeAccess",
        condition={"tag": "env", "value": "prod"},
    )


def test_one_attackstep_ttc_class(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"metaconcept": "EC2Instance", "attackstep": "HighPrivilegeAccess"},
        name="test_one_attackstep_ttc_class",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning,
        project=project,
        scope="class",
        id_="EC2Instance",
        ttc="Exponential,3",
        attackstep="highPrivilegeAccess",
    )


def test_one_attackstep_ttc_class_tag(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={
            "metaconcept": "EC2Instance",
            "attackstep": "HighPrivilegeAccess",
            "tags": {"env": "prod"},
        },
        name="test_one_attackstep_ttc_class",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning,
        project=project,
        scope="class",
        id_="EC2Instance",
        ttc="Exponential,3",
        attackstep="highPrivilegeAccess",
        condition={"tag": "env", "value": "prod"},
    )


def test_one_attackstep_ttc_object(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={"object_name": "i-1", "attackstep": "HighPrivilegeAccess"},
        name="test_one_attackstep_ttc_object",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning,
        project=project,
        scope="object",
        name="i-1",
        ttc="Exponential,3",
        id_=151,
        attackstep="highPrivilegeAccess",
    )


def test_one_attackstep_ttc_object(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="ttc",
        op="apply",
        filterdict={
            "metaconcept": "EC2Instance",
            "object_name": "i-1",
            "attackstep": "HighPrivilegeAccess",
        },
        name="test_one_attackstep_ttc_object",
        ttc="Exponential,3",
    )
    verify_tuning_response(
        tuning,
        project=project,
        scope="object",
        name="i-1",
        class_="EC2Instance",
        ttc="Exponential,3",
        id_=151,
        attackstep="highPrivilegeAccess",
    )


# Defense probability


def test_defense_probability_all(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="probability",
        op="apply",
        filterdict={},
        name="test_defense_probability_all",
        probability="0.5",
    )
    verify_tuning_response(
        tuning,
        project=project,
        scope="any",
        attackstep="",
        probability="0.5",
    )


def test_defense_probability_all_tag(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="probability",
        op="apply",
        filterdict={"tags": {"env": "prod"}},
        name="test_defense_probability_class",
        probability="0.5",
    )
    verify_tuning_response(
        tuning,
        project=project,
        scope="any",
        attackstep="",
        probability="0.5",
        condition={"tag": "env", "value": "prod"},
    )


def test_defense_probability_tag_one_defense(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="probability",
        op="apply",
        filterdict={"defense": "Patched", "tags": {"env": "prod"}},
        name="test_defense_probability_class",
        probability="0.5",
    )
    verify_tuning_response(
        tuning,
        project=project,
        scope="any",
        attackstep="",
        defense="Patched",
        probability="0.5",
        condition={"tag": "env", "value": "prod"},
    )


def test_defense_probability_class_all_defense(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="probability",
        op="apply",
        filterdict={"metaconcept": "EC2Instance"},
        name="test_defense_probability_class",
        probability="0.5",
    )
    verify_tuning_response(
        tuning,
        project=project,
        id_="EC2Instance",
        scope="class",
        probability="0.5",
        attackstep="",
    )


def test_defense_probability_class_one_defense(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="probability",
        op="apply",
        filterdict={"metaconcept": "EC2Instance", "defense": "Patched"},
        name="test_defense_probability_class",
        probability="0.5",
    )
    verify_tuning_response(
        tuning,
        project=project,
        id_="EC2Instance",
        scope="class",
        probability="0.5",
        attackstep="",
        defense="Patched",
    )


def test_defense_probability_class_tag_all_defense(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="probability",
        op="apply",
        filterdict={"metaconcept": "EC2Instance", "tags": {"env": "prod"}},
        name="test_defense_probability_class",
        probability="0.5",
    )
    verify_tuning_response(
        tuning,
        project=project,
        id_="EC2Instance",
        scope="class",
        probability="0.5",
        attackstep="",
        condition={"tag": "env", "value": "prod"},
    )


def test_defense_probability_class_tag_one_defense(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="probability",
        op="apply",
        filterdict={
            "metaconcept": "EC2Instance",
            "defense": "Patched",
            "tags": {"env": "prod"},
        },
        name="test_defense_probability_class",
        probability="0.5",
    )
    verify_tuning_response(
        tuning,
        project=project,
        id_="EC2Instance",
        scope="class",
        probability="0.5",
        defense="Patched",
        attackstep="",
        condition={"tag": "env", "value": "prod"},
    )


def test_defense_probability_object_all_defense(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="probability",
        op="apply",
        filterdict={"object_name": "i-1"},
        name="test_defense_probability_class",
        probability="0.5",
    )
    verify_tuning_response(
        tuning,
        project=project,
        name="i-1",
        scope="object",
        probability="0.5",
        attackstep="",
        id_=151,
    )


def test_defense_probability_object_one_defense(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="probability",
        op="apply",
        filterdict={"defense": "Patched", "object_name": "i-1"},
        name="test_defense_probability_class",
        probability="0.5",
    )
    verify_tuning_response(
        tuning,
        project=project,
        name="i-1",
        scope="object",
        probability="0.5",
        attackstep="",
        defense="Patched",
        id_=151,
    )


def test_defense_probability_class_object_all_defense(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="probability",
        op="apply",
        filterdict={"metaconcept": "EC2Instance", "object_name": "i-1"},
        name="test_defense_probability_class",
        probability="0.5",
    )
    verify_tuning_response(
        tuning,
        project=project,
        class_="EC2Instance",
        name="i-1",
        scope="object",
        probability="0.5",
        attackstep="",
        id_=151,
    )


def test_defense_probability_class_object_one_defense(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="probability",
        op="apply",
        filterdict={
            "metaconcept": "EC2Instance",
            "defense": "Patched",
            "object_name": "i-1",
        },
        name="test_defense_probability_class",
        probability="0.5",
    )
    verify_tuning_response(
        tuning,
        project=project,
        class_="EC2Instance",
        name="i-1",
        scope="object",
        probability="0.5",
        attackstep="",
        defense="Patched",
        id_=151,
    )


# Set tags


def test_tag_all(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="tag",
        op="apply",
        filterdict={},
        name="test_defense_probability_class",
        tags={"a": "b"},
    )
    verify_tuning_response(
        tuning,
        project=project,
        scope="any",
        attackstep="",
        tag="a",
        value="b",
    )


def test_tag_all_tag(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="tag",
        op="apply",
        filterdict={"tags": {"env": "prod"}},
        name="test_defense_probability_class",
        tags={"a": "b"},
    )
    verify_tuning_response(
        tuning,
        project=project,
        scope="any",
        attackstep="",
        tag="a",
        value="b",
        condition={"tag": "env", "value": "prod"},
    )


def test_tag_class(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="tag",
        op="apply",
        filterdict={"metaconcept": "EC2Instance"},
        name="test_defense_probability_class",
        tags={"a": "b"},
    )
    verify_tuning_response(
        tuning,
        project=project,
        id_="EC2Instance",
        scope="class",
        attackstep="",
        tag="a",
        value="b",
    )


def test_tag_class_tag(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="tag",
        op="apply",
        filterdict={"metaconcept": "EC2Instance", "tags": {"env": "prod"}},
        name="test_defense_probability_class",
        tags={"a": "b"},
    )
    verify_tuning_response(
        tuning,
        project=project,
        id_="EC2Instance",
        scope="class",
        attackstep="",
        tag="a",
        value="b",
        condition={"tag": "env", "value": "prod"},
    )


def test_tag_object(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="tag",
        op="apply",
        filterdict={"object_name": "i-1"},
        name="test_defense_probability_object",
        tags={"a": "b"},
    )
    verify_tuning_response(
        tuning,
        project=project,
        name="i-1",
        id_=151,
        scope="object",
        attackstep="",
        tag="a",
        value="b",
    )


def test_tag_object_class(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="tag",
        op="apply",
        filterdict={"metaconcept": "EC2Instance", "object_name": "i-1"},
        name="test_defense_probability_object_class",
        tags={"a": "b"},
    )
    verify_tuning_response(
        tuning,
        project=project,
        class_="EC2Instance",
        id_=151,
        name="i-1",
        scope="object",
        attackstep="",
        tag="a",
        value="b",
    )


def test_delete(client, project, model):
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="tag",
        op="apply",
        filterdict={"metaconcept": "EC2Instance", "object_name": "i-1"},
        name="test_defense_probability_object_class",
        tags={"a": "b"},
    )
    tuning.delete()
    assert project.list_tunings() == []


def test_list(client, project, model):
    assert project.list_tunings() == []
    tuning = client.tunings.create_tuning(
        project,
        model,
        tuning_type="tag",
        op="apply",
        filterdict={"metaconcept": "EC2Instance", "object_name": "i-1"},
        name="test_defense_probability_object_class",
        tags={"a": "b"},
    )
    curr_tunings = project.list_tunings()
    assert len(curr_tunings) == 1, curr_tunings
