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

import json

from requests import Response


class StatusCodeException(Exception):
    def __init__(
        self, status_code: int, method: str, url: str, response: Response
    ) -> None:
        self.status_code = response.status_code
        self.method = method
        self.url = url
        try:
            self.json = response.json()
            self.content = json.dumps(self.json, indent=2)
        except ValueError:
            self.json = None
            self.content = response.text
        message = "\n".join(
            [
                f"Unexpected status code {self.status_code} != {status_code} for {self.method} {self.url}",
                "Content:",
                self.content,
            ]
        )
        super().__init__(message)
