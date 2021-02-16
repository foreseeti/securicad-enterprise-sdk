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

import base64
import json
import time
from typing import TYPE_CHECKING, Any, BinaryIO, Dict, List, Optional, Tuple

from securicad.enterprise.model import Model

if TYPE_CHECKING:
    from securicad.enterprise.client import Client
    from securicad.enterprise.projects import Project


class ModelInfo:
    def __init__(
        self,
        client: "Client",
        pid: str,
        mid: str,
        name: str,
        description: str,
        threshold: int,
        samples: int,
        meta_data: Dict[str, Any],
        is_valid: Optional[bool],
        validation_issues: str,
    ) -> None:
        self.client = client
        self.pid = pid
        self.mid = mid
        self.name = name
        self.description = description
        self.threshold = threshold
        self.samples = samples
        self.meta_data = meta_data
        self.is_valid = is_valid
        self.validation_issues = validation_issues

    @staticmethod
    def __get_model_data(
        client: "Client", pid: str, mid: str
    ) -> Tuple[int, int, Dict[str, Any]]:
        model_data = client._post("modeldata", {"pid": pid, "mid": mid})
        return model_data["threshold"], model_data["samples"], model_data["metadata"]

    @staticmethod
    def from_dict(client: "Client", dict_model: Dict[str, Any]) -> "ModelInfo":
        threshold, samples, meta_data = ModelInfo.__get_model_data(
            client, dict_model["pid"], dict_model["mid"]
        )

        return ModelInfo(
            client=client,
            pid=dict_model["pid"],
            mid=dict_model["mid"],
            name=dict_model["name"],
            description=dict_model["description"],
            threshold=threshold,
            samples=samples,
            meta_data=meta_data,
            is_valid=Models._get_is_valid(dict_model["valid"]),
            validation_issues=dict_model["validation_issues"],
        )

    def update(
        self,
        *,
        name: Optional[str] = None,
        description: Optional[str] = None,
        threshold: Optional[int] = None,
        samples: Optional[int] = None,
    ) -> None:
        data: Dict[str, Any] = {"pid": self.pid, "mid": self.mid}
        if name is not None:
            data["name"] = name
        if description is not None:
            data["description"] = description
        if threshold is not None:
            data["threshold"] = threshold
        if samples is not None:
            data["samples"] = samples
        dict_model = self.client._post("model", data)
        threshold, samples, _ = ModelInfo.__get_model_data(
            self.client, self.pid, self.mid
        )
        self.name = dict_model["name"]
        self.description = dict_model["description"]
        self.threshold = threshold
        self.samples = samples

    def delete(self) -> None:
        self.client._delete("models", {"pid": self.pid, "mids": [self.mid]})

    def lock(self) -> None:
        self.client._post("model/lock", {"mid": self.mid})

    def release(self) -> None:
        self.client._post("model/release", {"mid": self.mid})

    def get_scad(self) -> bytes:
        data: Dict[str, Any] = {"pid": self.pid, "mids": [self.mid]}
        scad = self.client._post("model/file", data)
        scad_base64 = scad["data"].encode("utf-8")
        scad_bytes = base64.b64decode(scad_base64, validate=True)
        return scad_bytes

    def get_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {"pid": self.pid, "mids": [self.mid]}
        dict_model = self.client._post("model/json", data)
        return dict_model

    def get_model(self) -> Model:
        return Model(self.get_dict())


class Models:
    def __init__(self, client: "Client") -> None:
        self.client = client

    @staticmethod
    def _get_is_valid(valid: int) -> Optional[bool]:
        if valid == 0:
            return None
        if valid == 1:
            return True
        if valid == 2:
            return False
        raise ValueError(f"Invalid model validity {valid}")

    def __list_dict_models(self, project: "Project") -> List[Dict[str, Any]]:
        dict_models = self.client._post("models", {"pid": project.pid})
        return dict_models

    def __wait_for_model_validation(self, project: "Project", mid: str) -> ModelInfo:
        while True:
            for dict_model in self.__list_dict_models(project):
                if dict_model["mid"] != mid:
                    continue
                if Models._get_is_valid(dict_model["valid"]) is not None:
                    return ModelInfo.from_dict(
                        client=self.client, dict_model=dict_model
                    )
                break
            time.sleep(1)

    def list_models(self, project: "Project") -> List[ModelInfo]:
        dict_models = self.__list_dict_models(project)
        models = []
        for dict_model in dict_models:
            models.append(
                ModelInfo.from_dict(client=self.client, dict_model=dict_model)
            )
        return models

    def get_model_by_mid(self, project: "Project", mid: str) -> ModelInfo:
        dict_models = self.__list_dict_models(project)
        for dict_model in dict_models:
            if dict_model["mid"] == mid:
                return ModelInfo.from_dict(client=self.client, dict_model=dict_model)
        raise ValueError(f"Invalid model {mid}")

    def get_model_by_name(self, project: "Project", name: str) -> ModelInfo:
        dict_models = self.__list_dict_models(project)
        for dict_model in dict_models:
            if dict_model["name"] == name:
                return ModelInfo.from_dict(client=self.client, dict_model=dict_model)
        for dict_model in dict_models:
            if dict_model["name"].lower() == name.lower():
                return ModelInfo.from_dict(client=self.client, dict_model=dict_model)
        raise ValueError(f"Invalid model {name}")

    def save(self, project: "Project", model: Model) -> ModelInfo:
        data: Dict[str, Any] = {"pid": project.pid, "model": model.model}
        self.client._post("savemodel", data)
        return self.__wait_for_model_validation(project, model.model["mid"])

    def save_as(self, project: "Project", model: Model, name: str) -> ModelInfo:
        model.model["name"] = f"{name}.sCAD"
        data: Dict[str, Any] = {"pid": project.pid, "model": model.model}
        dict_model = self.client._post("savemodelas", data)
        return self.__wait_for_model_validation(project, dict_model["mid"])

    def upload_scad_model(
        self,
        project: "Project",
        filename: str,
        file: BinaryIO,
        description: Optional[str] = None,
    ) -> ModelInfo:
        """Uploads an ``.sCAD`` model file.

        :param project: The :class:`Project` to upload the model to.
        :param filename: The name of the model file, including the ``.sCAD`` extension.
        :param file: The model to upload, either a file opened in binary mode, or a :class:`io.BytesIO` object.
        :param description: (optional) The description of the model.
        :return: A :class:`ModelInfo` object representing the uploaded model.
        """
        file_bytes = file.read()
        file_base64 = base64.b64encode(file_bytes).decode("utf-8")
        file_data = {
            "filename": filename,
            "file": file_base64,
            "type": "scad",
        }
        if description is not None:
            file_data["description"] = description
        data: Dict[str, Any] = {"pid": project.pid, "files": [[file_data]]}
        dict_model = self.client._put("models", data)[0]
        return self.__wait_for_model_validation(project, dict_model["mid"])

    def upload_aws_model(
        self,
        project: "Project",
        name: str,
        cli_files: Optional[List[Dict[str, Any]]] = None,
        vul_files: Optional[List[Dict[str, Any]]] = None,
    ) -> ModelInfo:
        """Generates a model from AWS data.

        :param project: The :class:`Project` to upload the model to.
        :param name: The name of the model.
        :param cli_files: (optional) A list of CLI data created with ``aws_import_cli``.
        :param vul_files: (optional) A list of vulnerability data.
        :return: A :class:`ModelInfo` object representing the uploaded model.
        """

        def json_to_base64(json_object: Dict[str, Any]) -> str:
            json_string = json.dumps(json_object, allow_nan=False, indent=2)
            json_bytes = json_string.encode("utf-8")
            json_base64 = base64.b64encode(json_bytes).decode("utf-8")
            return json_base64

        def get_json_file(
            sub_parser: str, name: str, json_object: Dict[str, Any]
        ) -> Dict[str, Any]:
            return {
                "sub_parser": sub_parser,
                "name": name,
                "content": json_to_base64(json_object),
            }

        def get_cli_files() -> List[Dict[str, Any]]:
            files = []
            if cli_files is not None:
                for cli_file in cli_files:
                    files.append(get_json_file("aws-cli-parser", "aws.json", cli_file))
            return files

        def get_vul_files() -> List[Dict[str, Any]]:
            files = []
            if vul_files is not None:
                for vul_file in vul_files:
                    files.append(get_json_file("aws-vul-parser", "vul.json", vul_file))
            return files

        data: Dict[str, Any] = {
            "parser": "aws-parser",
            "name": name,
            "files": get_cli_files() + get_vul_files(),
        }
        dict_model = self.client._post(f"projects/{project.pid}/multiparser", data)
        return self.__wait_for_model_validation(project, dict_model["mid"])
