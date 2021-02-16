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

from typing import Any, Dict, Optional, Tuple, Union
from urllib.parse import urljoin

import requests

from securicad.enterprise.exceptions import StatusCodeException
from securicad.enterprise.models import Models
from securicad.enterprise.organizations import Organizations
from securicad.enterprise.projects import Projects
from securicad.enterprise.scenarios import Scenarios
from securicad.enterprise.simulations import Simulations
from securicad.enterprise.users import Users


class Client:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        organization: Optional[str] = None,
        backend_url: Optional[str] = None,
        cacert: Optional[Union[bool, str]] = None,
        client_cert: Optional[Union[str, Tuple[str, str]]] = None,
    ) -> None:
        self.__init_urls(base_url, backend_url)
        self.__init_session(cacert, client_cert)

        self.organizations = Organizations(client=self)
        self.users = Users(client=self)
        self.projects = Projects(client=self)
        self.models = Models(client=self)
        self.scenarios = Scenarios(client=self)
        self.simulations = Simulations(client=self)

        self.login(username, password, organization)

    def __init_urls(self, base_url: str, backend_url: Optional[str]) -> None:
        self.__base_url = urljoin(base_url, "/")
        if backend_url is None:
            backend_url = base_url
        self.__backend_url = urljoin(backend_url, "/api/v1/")

    def __init_session(
        self,
        cacert: Optional[Union[bool, str]],
        client_cert: Optional[Union[str, Tuple[str, str]]],
    ) -> None:
        def get_user_agent():
            # pylint: disable=import-outside-toplevel
            import securicad.enterprise

            return f"Enterprise SDK {securicad.enterprise.__version__}"

        self.__session = requests.Session()
        self.__session.headers["User-Agent"] = get_user_agent()

        # Server certificate verification
        if cacert is not None:
            if cacert is False:
                # pylint: disable=no-member
                requests.packages.urllib3.disable_warnings(
                    requests.packages.urllib3.exceptions.InsecureRequestWarning
                )
            self.__session.verify = cacert

        # Client certificate
        if client_cert is not None:
            self.__session.cert = client_cert

    def _set_access_token(self, access_token: Optional[str]) -> None:
        if access_token is None and "Authorization" in self.__session.headers:
            del self.__session.headers["Authorization"]
        else:
            self.__session.headers["Authorization"] = f"JWT {access_token}"

    def __request(self, method: str, endpoint: str, data: Any, status_code: int) -> Any:
        url = urljoin(self.__backend_url, endpoint)
        response = self.__session.request(method, url, json=data)
        if response.status_code != status_code:
            raise StatusCodeException(status_code, method, url, response)
        return response.json()["response"]

    def _get(self, endpoint: str, data: Any = None, status_code: int = 200) -> Any:
        return self.__request("GET", endpoint, data, status_code)

    def _post(self, endpoint: str, data: Any = None, status_code: int = 200) -> Any:
        return self.__request("POST", endpoint, data, status_code)

    def _put(self, endpoint: str, data: Any = None, status_code: int = 200) -> Any:
        return self.__request("PUT", endpoint, data, status_code)

    def _delete(self, endpoint: str, data: Any = None, status_code: int = 200) -> Any:
        return self.__request("DELETE", endpoint, data, status_code)

    def login(
        self, username: str, password: str, organization: Optional[str] = None
    ) -> None:
        data: Dict[str, Any] = {"username": username, "password": password}
        if organization is not None:
            data["organization"] = organization
        access_token = self._post("auth/login", data)["access_token"]
        self._set_access_token(access_token)

    def logout(self) -> None:
        self._post("auth/logout")
        self._set_access_token(None)

    def refresh(self) -> None:
        access_token = self._post("auth/refresh")["access_token"]
        self._set_access_token(access_token)
