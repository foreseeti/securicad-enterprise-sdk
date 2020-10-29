# Copyright 2020 Foreseeti AB
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

import base64
import json
import time
from datetime import datetime

import requests

import securicad.enterprise
from securicad.enterprise.model import Model


def serialize_datetime(o):
    if isinstance(o, datetime):
        return o.__str__()


class Client:
    def __init__(self, url, username, password, org, cacert):
        self.web_url = url
        self.base_url = f"{url}/api/v1"

        self.session = requests.Session()
        if cacert:
            self.session.verify = cacert
        else:
            self.session.verify = False
            requests.packages.urllib3.disable_warnings(
                requests.packages.urllib3.exceptions.InsecureRequestWarning
            )
        self.session.headers["User-Agent"] = f"Enterprise SDK {securicad.enterprise.__version__}"
        self.session.headers["Authorization"] = self.__authenticate(username, password, org)

    def __authenticate(self, username, password, org):
        url = f"{self.base_url}/auth/login"
        data = {"username": username, "password": password}
        if org:
            data["organization"] = org
        res = self.session.post(url, json=data)
        res.raise_for_status()
        if res.status_code == 200:
            access_token = res.json()["response"]["access_token"]
            jwt_token = f"JWT {access_token}"
            return jwt_token

    def __encode_data(self, data):
        if isinstance(data, dict):
            content = json.dumps(data, default=serialize_datetime).encode("utf-8")
        elif isinstance(data, bytes):
            content = data
        else:
            raise ValueError(f"a bytes-like object or dict is required, not {type(data)}")
        return content

    def add_model(self, pid, json_data, name):
        model_id = self.__add_model(pid, json_data, name)
        model = self.get_model(pid, model_id)
        return model_id, model

    def __add_model(self, pid, json_data, name):
        url = f"{self.base_url}/models"

        model_content = self.__encode_data(json_data)
        model_base64d = base64.b64encode(model_content).decode("utf-8")

        data = {
            "pid": pid,
            "files": [
                [
                    {
                        "file": model_base64d,
                        "filename": f"{name}.json",
                        "type": "aws",
                        "tags": [],
                    }
                ]
            ],
        }

        res = self.session.put(url, json=data)
        res.raise_for_status()
        mid = res.json()["response"][0]["mid"]
        while True:
            res = self.session.post(url, json={"pid": pid})
            res.raise_for_status()
            for model in res.json()["response"]:
                if mid == model["mid"] and model["valid"] > 0:
                    return mid
            time.sleep(1)

    def get_project(self, name):
        url = f"{self.base_url}/projects"
        res = self.session.post(url)
        res.raise_for_status()
        for project in res.json()["response"]:
            if project["name"] == name:
                return project["pid"]
        raise ValueError(f"project name '{name}' does not exist")

    def get_model(self, pid, mid):
        url = f"{self.base_url}/model/json"

        data = {"pid": pid, "mids": [mid]}
        res = self.session.post(url, json=data)
        res.raise_for_status()

        return Model(res.json()["response"])

    def save_model(self, pid, model):
        mid = model.model["mid"]
        self.__lock_model(mid)
        self.__save_model(pid, model)
        self.__release_model(mid)

    def __save_model(self, pid, model):
        url = f"{self.base_url}/savemodel"

        data = {"pid": pid, "model": model.model}
        res = self.session.post(url, json=data)
        res.raise_for_status()

        return res.json()["response"]

    def save_model_as(self, pid, model, name):
        url = f"{self.base_url}/savemodelas"

        model.model["name"] = f"{name}.sCAD"
        data = {"pid": pid, "model": model.model}
        res = self.session.post(url, json=data)
        res.raise_for_status()
        model.model["mid"] = res.json()["response"]["mid"]
        model.id = model.model["mid"]

        return model.id

    def __lock_model(self, mid):
        url = f"{self.base_url}/model/lock"

        data = {
            "mid": mid,
        }
        res = self.session.post(url, json=data)
        res.raise_for_status()

        return res.json()["response"]

    def __release_model(self, mid):
        url = f"{self.base_url}/model/release"

        data = {"mid": mid}
        res = self.session.post(url, json=data)
        res.raise_for_status()

        return res.json()["response"]

    def start_simulation(self, pid, mid, name):
        scenario_id = self.__start_scenario(pid, mid, name, "")
        simulation_id = self.__start_simulation(pid, scenario_id, name)
        return simulation_id

    def __start_scenario(self, pid, mid, name, description):
        url = f"{self.base_url}/scenario"

        data = {
            "pid": pid,
            "mid": mid,
            "name": name,
            "description": description,
        }
        res = self.session.put(url, json=data)
        res.raise_for_status()

        return res.json()["response"]["tid"]

    def __start_simulation(self, pid, tid, name):
        url = f"{self.base_url}/simulation"

        data = {
            "pid": pid,
            "tid": tid,
            "cids": [],
            "name": name,
        }

        res = self.session.put(url, json=data)
        res.raise_for_status()
        simid = res.json()["response"]["simid"]
        return simid, tid

    def get_results(self, pid, tid, simid):
        self.__poll_results(pid, tid, simid)
        result = self.__get_results(pid, simid)
        result["report_url"] = f"{self.web_url}/project/{pid}/scenario/{tid}/report/{simid}"
        return result

    def __poll_results(self, pid, tid, simid):
        url = f"{self.base_url}/scenario/data"

        data = {"pid": pid, "tid": tid}

        while True:
            res = self.session.post(url, json=data)
            res.raise_for_status()
            resdata = res.json()["response"]
            results = resdata["results"]
            if simid in results:
                if results[simid]["progress"] == 100:
                    return
            else:
                raise ValueError(f"simulation id '{simid}' does not exist")
            time.sleep(1)

    def __get_results(self, pid, simid):
        url = f"{self.base_url}/simulation/data"

        data = {"pid": pid, "simid": simid}
        res = self.session.post(url, json=data)
        res.raise_for_status()

        return res.json()["response"]

    def get_metadata(self):
        url = f"{self.base_url}/metadata"
        res = self.session.get(url)
        res.raise_for_status()
        metadata = res.json()["response"]
        metalist = []
        for asset, data in metadata["assets"].items():
            attacksteps = []
            for a in data["attacksteps"]:
                attacksteps.append(
                    {
                        "name": a["name"],
                        "description": a["description"],
                    }
                )
            metalist.append(
                {
                    "name": asset,
                    "description": data["description"],
                    "attacksteps": attacksteps,
                }
            )
        return sorted(metalist, key=lambda k: k["name"])
