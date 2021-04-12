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

from typing import TYPE_CHECKING, Any, BinaryIO, Dict, List, NewType, Optional

if TYPE_CHECKING:
    from securicad.enterprise.client import Client
    from securicad.enterprise.projects import Project


class Tuning:
    def __init__(
        self,
        client: "Client",
        pid: str,
        tuning_id: str,
        scope: str,
        ttc: str,
        condition: "TuningCondition" = None,
        consequence: "Consequence" = None,
        defense: str = None,
        id_: str = None,
        probability: str = None,
        class_: str = None,
        name: str = None,
        attackstep: str = None,
        tag: str = None,
        value: str = None,
    ) -> None:
        self.client = client
        self.pid = pid
        self.tuning_id = tuning_id
        self.id_ = id_
        self.attackstep = attackstep
        self.scope = scope
        self.ttc = ttc
        if condition:
            self.condition = condition
        else:
            self.condition = {"tag": "", "value": ""}
        self.consequence = consequence
        self.defense = defense
        self.probability = probability
        self.class_ = class_
        self.name = name
        self.tag = tag
        self.value = value

    @staticmethod
    def from_dict(client, dict_tuning: Dict[str, Any]) -> "Tuning":
        return Tuning(
            client=client,
            pid=dict_tuning["pid"],
            tuning_id=dict_tuning["cid"],
            attackstep=dict_tuning["config"]["attackstep"],
            scope=dict_tuning["config"]["scope"],
            condition=dict_tuning["config"]["condition"],
            consequence=dict_tuning["config"]["consequence"],
            defense=dict_tuning["config"]["defense"],
            id_=dict_tuning["config"].get("id", None),
            probability=dict_tuning["config"]["probability"],
            ttc=dict_tuning["config"]["ttc"],
            class_=dict_tuning["config"].get("class", None),
            name=dict_tuning["config"].get("name", None),
            tag=dict_tuning["config"].get("tag", None),
            value=dict_tuning["config"].get("value", None),
        )


class Tunings:
    def __init__(self, client: "Client") -> None:
        self.client = client

    def list_tunings(self, project: "Project"):
        data: Dict[str, Any] = {"pid": project.pid}
        resp = self.client._post("tunings", data)
        retr = []
        for tuning_id, tuning_data in resp["configs"].items():
            tuning_dict = {"pid": project.pid, "tuning_id": tuning_id, **tuning_data}
            retr.append(Tuning.from_dict(self.client, tuning_dict))
        return retr

    def _convert_to_old_format(
        project,
        model,
        tuning_type,
        op,
        filterdict,
        name,
        ttc,
        tags,
        consequence,
        probability,
    ):
        def make_first_letter_lowercase(text):
            if text:
                return text[0].lower() + text[1:]
            else:
                return ""

        def find_object(model, name, metaconcept):
            data = model.model
            matching_names = []
            for objid, objdata in data["objects"].items():
                if objdata["name"] == name:
                    matching_names.append(objdata)
                    return objdata["eid"]
            if not matching_names:
                raise ValueError(f"Object with name '{name}' not found")
            elif len(matching_names) == 1:
                return matching_names[0]["id"]

            # we have several matching, match metaconcept
            matching_meta = []
            for objdata in matching_names:
                if objdata["metaconcept"] == metaconcept:
                    matching_meta.append(objdata)
            if not matching_meta:
                raise ValueError(
                    f"Several objects with matching name '{name}' found, but none of the supplied type '{metaconcept}'"
                )
            elif len(matching_meta) == 1:
                return matching_meta[0]["id"]
            else:
                raise ValueError(
                    f"Several objects with matching name '{name}' found of the supplied type '{metaconcept}'"
                )

        config = {}

        # set scope, name, id
        if "object_name" in filterdict:
            config["scope"] = "object"
            config["name"] = filterdict["object_name"]
            config["attackstep"] = make_first_letter_lowercase(
                filterdict.get("attackstep", None)
            )
            if "metaconcept" in filterdict:
                config["class"] = filterdict["metaconcept"]
            config["id"] = find_object(
                model, filterdict["object_name"], filterdict.get("metaconcept", None)
            )
        elif "metaconcept" in filterdict:
            config["scope"] = "class"
            config["id"] = filterdict["metaconcept"]
            config["attackstep"] = make_first_letter_lowercase(
                filterdict.get("attackstep", None)
            )
        else:
            config["scope"] = "any"
            config["id"] = None
            config["attackstep"] = make_first_letter_lowercase(
                filterdict.get("attackstep", None)
            )

        # set condition dict
        if "tags" in filterdict and filterdict["tags"].keys():
            if len(filterdict["tags"].keys()) > 1:
                # old tuning format only support filtering by one tag
                raise ValueError(
                    "current ES tuning format only supports one tag when filtering"
                )

            key = list(filterdict["tags"].keys())[0]
            config["condition"] = {"tag": key, "value": filterdict["tags"][key]}
        else:
            config["condition"] = {"tag": "", "value": ""}

        # consequence
        if consequence:
            config["consequence"] = str(consequence)
        else:
            config["consequence"] = None

        # defence
        if "defense" in filterdict:
            config["defense"] = filterdict["defense"]
        else:
            config["defense"] = None

        # tags
        if tuning_type == "tags" and tags:
            if len(tags) > 1:
                raise ValueError(
                    "Current ES tuning format only supports setting one tag per tuning"
                )
            key, val = list(tags.items())[0]
            config["tag"] = key
            config["value"] = val

        config["ttc"] = ttc
        config["probability"] = probability
        data: Dict[str, Any] = {"pid": project.pid, "configs": [config]}
        return data

    def create_tuning(
        self,
        project: "Project",
        model: "Model",
        tuning_type: str,
        op: str,
        filterdict: Dict[str, Any],
        name: str = None,
        ttc="",
        tags=None,
        consequence: "Consequence" = None,
        probability: str = None,
    ):
        if tuning_type not in ["attacker", "ttc", "tags", "probability", "consequence"]:
            raise ValueError(f"Unknown {tuning_type=}")
        data = Tunings._convert_to_old_format(
            project,
            model,
            tuning_type,
            op=op,
            filterdict=filterdict,
            name=name,
            ttc=ttc,
            tags=tags,
            consequence=consequence,
            probability=probability,
        )
        import json

        # print(f"sending data:\n{json.dumps(data)}")
        dict_tuning = self.client._put("tunings", data)[0]
        # print(dict_tuning)
        return Tuning.from_dict(client=self.client, dict_tuning=dict_tuning)
