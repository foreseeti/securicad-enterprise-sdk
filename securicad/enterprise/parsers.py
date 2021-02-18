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

import io
import json
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from securicad.enterprise.client import Client
    from securicad.enterprise.models import ModelInfo
    from securicad.enterprise.projects import Project


class Parsers:
    def __init__(self, client: "Client") -> None:
        self.client = client

    def list_parsers(self) -> List[Dict[str, Any]]:
        return self.client._get("parsers")

    def generate_aws_model(
        self,
        project: "Project",
        name: str,
        cli_files: Optional[List[Dict[str, Any]]] = None,
        vul_files: Optional[List[Dict[str, Any]]] = None,
    ) -> "ModelInfo":
        """Generates a model from AWS data.

        :param project: The :class:`Project` to add the generated model to.
        :param name: The name of the generated model.
        :param cli_files: (optional) A list of CLI data created with ``aws_import_cli``.
        :param vul_files: (optional) A list of vulnerability data.
        :return: A :class:`ModelInfo` object representing the generated model.
        """

        def get_file_io(dict_file: Dict[str, Any]) -> io.BytesIO:
            file_str = json.dumps(dict_file, allow_nan=False, indent=2)
            file_bytes = file_str.encode("utf-8")
            return io.BytesIO(file_bytes)

        def get_file(
            sub_parser: str, name: str, dict_file: Dict[str, Any]
        ) -> Dict[str, Any]:
            return {
                "sub_parser": sub_parser,
                "name": name,
                "file": get_file_io(dict_file),
            }

        def get_files() -> List[Dict[str, Any]]:
            files = []
            if cli_files is not None:
                for cli_file in cli_files:
                    files.append(get_file("aws-cli-parser", "aws.json", cli_file))
            if vul_files is not None:
                for vul_file in vul_files:
                    files.append(get_file("aws-vul-parser", "vul.json", vul_file))
            return files

        return self.client.models.generate_model(
            project=project, parser="aws-parser", name=name, files=get_files()
        )
