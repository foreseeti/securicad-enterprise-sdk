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

PARSERS = [
    {
        "name": "aws-parser",
        "sub_parsers": [
            "aws-cli-parser",
            "aws-vul-parser",
        ],
    },
    {
        "name": "nmap",
        "sub_parsers": None,
    },
    {
        "name": "scad",
        "sub_parsers": None,
    },
]


def test_list_parsers(data):
    def assert_lists_eq(list1_name, list1, list2_name, list2):
        if list1 is not None and list2 is not None:
            assert len(list1) == len(
                list2
            ), f"len({list1_name}) != len({list2_name}), {len(list1)} != {len(list2)}"
            for item in list1:
                assert item in list2, f'Item "{item}" not in list "{list2_name}"'
            for item in list2:
                assert item in list1, f'Item "{item}" not in list "{list1_name}"'
        else:
            assert list1 is None
            assert list2 is None

    def assert_parsers_eq(actual_parsers, expected_parsers):
        assert len(actual_parsers) == len(
            expected_parsers
        ), f"len(actual_parsers) != len(expected_parsers), {len(actual_parsers)} == {len(expected_parsers)}"
        for actual_parser in actual_parsers:
            for expected_parser in expected_parsers:
                if actual_parser["name"] != expected_parser["name"]:
                    continue
                assert_lists_eq(
                    f"actual.{actual_parser['name']}.sub_parsers",
                    actual_parser["sub_parsers"],
                    f"expected.{expected_parser['name']}.sub_parsers",
                    expected_parser["sub_parsers"],
                )
                break
            else:
                assert (
                    False
                ), f"Parser {actual_parser['name']} not found in expected_parsers"
        for expected_parser in expected_parsers:
            for actual_parser in actual_parsers:
                if expected_parser["name"] != actual_parser["name"]:
                    continue
                assert_lists_eq(
                    f"expected.{expected_parser['name']}.sub_parsers",
                    expected_parser["sub_parsers"],
                    f"actual.{actual_parser['name']}.sub_parsers",
                    actual_parser["sub_parsers"],
                )
                break
            else:
                assert (
                    False
                ), f"Parser {expected_parser['name']} not found in actual_parsers"

    def assert_list_parsers(client):
        parsers = client.parsers.list_parsers()
        assert_parsers_eq(parsers, PARSERS)

    def assert_list_parsers_fails(client):
        with pytest.raises(StatusCodeException) as e:
            client.parsers.list_parsers()
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=401,
            method="GET",
            url=utils.get_url("parsers"),
            data={"msg": "Missing Authorization Header"},
        )

    for user_data in data["users"].values():
        client = utils.get_client(user_data["username"], user_data["password"])
        assert_list_parsers(client)
        client.logout()

    for org_data in data["organizations"].values():
        for user_data in org_data["users"].values():
            client = utils.get_client_org(
                user_data["username"], user_data["password"], org_data["name"]
            )
            assert_list_parsers(client)
            client.logout()

    client = utils.get_client_sysadmin()
    client.logout()
    assert_list_parsers_fails(client)


# TODO:
# test_generate_aws_model()
