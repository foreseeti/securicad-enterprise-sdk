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
import time
from typing import TYPE_CHECKING, Any, BinaryIO, Dict, List, Optional, Tuple

from securicad.model import Model

if TYPE_CHECKING:
    from securicad.enterprise.client import Client
    from securicad.enterprise.projects import Project


def _get_is_valid(valid: int) -> Optional[bool]:
    if valid == 0:
        return None
    if valid == 1:
        return True
    if valid == 2:
        return False
    raise ValueError(f"Invalid model validity {valid}")


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
    def from_dict(client: "Client", dict_model: Dict[str, Any]) -> "ModelInfo":
        threshold, samples, meta_data = client.models._get_model_data(
            dict_model["pid"], dict_model["mid"]
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
            is_valid=_get_is_valid(dict_model["valid"]),
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
        threshold, samples, _ = self.client.models._get_model_data(self.pid, self.mid)
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

    def save(self, model: Model) -> "ModelInfo":
        model.model["mid"] = self.mid
        model.model["name"] = self.name
        data: Dict[str, Any] = {"pid": self.pid, "model": model.model}
        self.client._post("savemodel", data)
        return self.client.models._wait_for_model_validation(self.pid, self.mid)


class Models:
    def __init__(self, client: "Client") -> None:
        self.client = client

    def _wait_for_model_validation(self, pid: str, mid: str) -> ModelInfo:
        while True:
            for dict_model in self._list_dict_models(pid):
                if dict_model["mid"] != mid:
                    continue
                if _get_is_valid(dict_model["valid"]) is not None:
                    return ModelInfo.from_dict(
                        client=self.client, dict_model=dict_model
                    )
                break
            time.sleep(1)

    def _list_dict_models(self, pid: str) -> List[Dict[str, Any]]:
        dict_models = self.client._post("models", {"pid": pid})
        return dict_models

    def _get_model_data(self, pid: str, mid: str) -> Tuple[int, int, Dict[str, Any]]:
        model_data = self.client._post("modeldata", {"pid": pid, "mid": mid})
        return model_data["threshold"], model_data["samples"], model_data["metadata"]

    def list_models(self, project: "Project") -> List[ModelInfo]:
        dict_models = self._list_dict_models(project.pid)
        models = []
        for dict_model in dict_models:
            models.append(
                ModelInfo.from_dict(client=self.client, dict_model=dict_model)
            )
        return models

    def get_model_by_mid(self, project: "Project", mid: str) -> ModelInfo:
        dict_models = self._list_dict_models(project.pid)
        for dict_model in dict_models:
            if dict_model["mid"] == mid:
                return ModelInfo.from_dict(client=self.client, dict_model=dict_model)
        raise ValueError(f"Invalid model {mid}")

    def get_model_by_name(self, project: "Project", name: str) -> ModelInfo:
        dict_models = self._list_dict_models(project.pid)
        for dict_model in dict_models:
            if dict_model["name"] == name:
                return ModelInfo.from_dict(client=self.client, dict_model=dict_model)
        for dict_model in dict_models:
            if dict_model["name"].lower() == name.lower():
                return ModelInfo.from_dict(client=self.client, dict_model=dict_model)
        raise ValueError(f"Invalid model {name}")

    def save_as(self, project: "Project", model: Model, name: str) -> ModelInfo:
        model.model["name"] = f"{name}.sCAD"
        data: Dict[str, Any] = {"pid": project.pid, "model": model.model}
        dict_model = self.client._post("savemodelas", data)
        return self._wait_for_model_validation(project.pid, dict_model["mid"])

    def upload_scad_model(
        self,
        project: "Project",
        filename: str,
        file_io: BinaryIO,
        description: Optional[str] = None,
    ) -> ModelInfo:
        """Uploads an ``.sCAD`` model file.

        :param project: The :class:`Project` to upload the model to.
        :param filename: The name of the model file, including the ``.sCAD`` extension.
        :param file_io: The model to upload, either a file opened in binary mode, or a :class:`io.BytesIO` object.
        :param description: (optional) The description of the model.
        :return: A :class:`ModelInfo` object representing the uploaded model.
        """

        def get_file_content(file_io: BinaryIO) -> str:
            file_bytes = file_io.read()
            file_base64 = base64.b64encode(file_bytes).decode("utf-8")
            return file_base64

        def get_file() -> Dict[str, Any]:
            _file = {
                "filename": filename,
                "file": get_file_content(file_io),
                "type": "scad",
            }
            if description is not None:
                _file["description"] = description
            return _file

        data: Dict[str, Any] = {"pid": project.pid, "files": [[get_file()]]}
        dict_model = self.client._put("models", data)[0]
        return self._wait_for_model_validation(project.pid, dict_model["mid"])

    def generate_model(
        self, project: "Project", parser: str, name: str, files: List[Dict[str, Any]]
    ) -> ModelInfo:
        """Generates a model with a parser.

        :param project: The :class:`Project` to add the generated model to.
        :param parser: The name of the parser to use.
        :param name: The name of the generated model.
        :param files: A list of dictionaries on the format

            .. code-block::

                {
                    "sub_parser": <sub-parser-name>,
                    "name": <file-name>,
                    "file": <binary-io>,
                }

            where:

            - ``<sub-parser-name>`` is the name of the sub-parser to use for the file
            - ``<file-name>`` is the name of the file
            - ``<binary-io>`` is either a file opened in binary mode, or a :class:`io.BytesIO` object.
        :return: A :class:`ModelInfo` object representing the generated model.
        """

        def get_file_content(file_io: BinaryIO) -> str:
            file_bytes = file_io.read()
            file_base64 = base64.b64encode(file_bytes).decode("utf-8")
            return file_base64

        def get_files() -> List[Dict[str, Any]]:
            _files = []
            for file_dict in files:
                _files.append(
                    {
                        "sub_parser": file_dict["sub_parser"],
                        "name": file_dict["name"],
                        "content": get_file_content(file_dict["file"]),
                    }
                )
            return _files

        data: Dict[str, Any] = {
            "parser": parser,
            "name": name,
            "files": get_files(),
        }
        dict_model = self.client._post(f"projects/{project.pid}/multiparser", data)
        return self._wait_for_model_validation(project.pid, dict_model["mid"])
