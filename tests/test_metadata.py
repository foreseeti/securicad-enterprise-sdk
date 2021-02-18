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

# isort: on


def test_get_metadata(data, awslang):
    def assert_get_metadata(client):
        metalist = client.metadata.get_metadata()
        expected_len = len(awslang)
        actual_len = len(metalist)
        assert (
            actual_len == expected_len
        ), f"len(metalist) {actual_len} != {expected_len}"

        for i in range(actual_len):
            expected_asset = awslang[i]
            actual_asset = metalist[i]
            assert (
                actual_asset["name"] == expected_asset["name"]
            ), f"Unexpected asset name \"{actual_asset['name']}\" != \"{expected_asset['name']}\""
            expected_attacksteps_len = len(expected_asset["attacksteps"])
            actual_attacksteps_len = len(actual_asset["attacksteps"])
            assert (
                actual_attacksteps_len == expected_attacksteps_len
            ), f"len({expected_asset['name']}[\"attacksteps\"]) {actual_attacksteps_len} != {expected_attacksteps_len}"

    def assert_get_metadata_fails(client):
        with pytest.raises(StatusCodeException) as e:
            client.metadata.get_metadata()
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=401,
            method="GET",
            url=utils.get_url("metadata"),
            data={"msg": "Missing Authorization Header"},
        )

    for user_data in data["users"].values():
        client = utils.get_client(user_data["username"], user_data["password"])
        assert_get_metadata(client)
        client.logout()

    for org_data in data["organizations"].values():
        for user_data in org_data["users"].values():
            client = utils.get_client_org(
                user_data["username"], user_data["password"], org_data["name"]
            )
            assert_get_metadata(client)
            client.logout()

    client = utils.get_client_sysadmin()
    client.logout()
    assert_get_metadata_fails(client)
