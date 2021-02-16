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

from collections import defaultdict


class Model:
    def __init__(self, model):
        self.model = model
        self.id = model["mid"]

    def disable_attackstep(self, metaconcept, attackstep, name=None):
        for oid, obj in self.model["objects"].items():
            if obj["metaconcept"] == metaconcept:
                if name and obj["name"] != name:
                    continue
                self.__set_evidence(oid, attackstep, distribution="Infinity")

    def set_high_value_assets(self, **kwargs):
        hv_list = kwargs.get("high_value_assets", [])

        # Collect the high value assets under their metaconcept
        hv_assets = defaultdict(list)
        [hv_assets[x["metaconcept"]].append(x) for x in hv_list]

        # Check if any of the objects are eligible as a high value asset
        for oid, obj in self.model["objects"].items():
            if obj["metaconcept"] in hv_assets:
                for hv_asset in hv_assets[obj["metaconcept"]]:
                    if self.__is_high_value_asset(obj, hv_asset):
                        self.__set_high_value_asset(oid, obj, hv_asset)

    def __is_high_value_asset(self, obj, hv_asset):
        # Check if a model object matches any of the high value assets
        if hv_asset.get("id") is None:
            return True
        if hv_asset["id"]["type"] == "name" and obj["name"] == hv_asset["id"]["value"]:
            return True
        elif hv_asset["id"]["type"] == "tag":
            if (
                obj.get("tags", {}).get(hv_asset["id"]["key"])
                == hv_asset["id"]["value"]
            ):
                return True
        elif hv_asset["id"]["type"] == "arn":
            if obj.get("tags", {}).get("arn") == hv_asset["id"]["value"]:
                return True
        return False

    def __set_high_value_asset(self, oid, obj, hv_asset):
        attackstep = hv_asset["attackstep"]
        consequence = 10
        if hv_asset.get("consequence") is not None:
            consequence = hv_asset.get("consequence")
        self.__set_evidence(oid, attackstep, consequence=consequence)

    def __set_evidence(self, oid, attackstep, consequence=None, distribution=None):
        for step in self.model["objects"][oid]["attacksteps"]:
            if step["name"] == attackstep:
                if consequence:
                    step["consequence"] = consequence
                if distribution:
                    step["distribution"] = distribution
                break
        else:
            self.model["objects"][oid]["attacksteps"].append(
                {
                    "name": attackstep,
                    "distribution": distribution,
                    "lowercost": None,
                    "uppercost": None,
                    "consequence": consequence,
                }
            )
