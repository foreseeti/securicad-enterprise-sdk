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


def test_whoami(data):
    def assert_whoami(client, user_data, org):
        user = client.users.whoami()
        utils.assert_user_data(user, user_data, org)

    def assert_whoami_fails(client):
        with pytest.raises(StatusCodeException) as e:
            client.users.whoami()
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=401,
            method="GET",
            url=utils.get_url("whoami"),
            data={"msg": "Missing Authorization Header"},
        )

    for user_data in data["users"].values():
        client = utils.get_client(user_data["username"], user_data["password"])
        assert_whoami(client, user_data, None)
        client.logout()

    for org_data in data["organizations"].values():
        for user_data in org_data["users"].values():
            client = utils.get_client_org(
                user_data["username"], user_data["password"], org_data["name"]
            )
            assert_whoami(client, user_data, org_data["name"])
            client.logout()

    client = utils.get_client_sysadmin()
    client.logout()
    assert_whoami_fails(client)


def test_change_password(data):
    def assert_password_correct(username, password, org):
        client = utils.get_client_org(username, password, org)

    def assert_password_incorrect(username, password, org):
        with pytest.raises(StatusCodeException) as e:
            utils.get_client_org(username, password, org)
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=401,
            method="POST",
            url=utils.get_url("auth/login"),
            data={"error": "Invalid login"},
        )

    def assert_change_password(client, username, old_password, new_password, org):
        assert_password_correct(username, old_password, org)
        assert_password_incorrect(username, new_password, org)
        utils.assert_access_token(client)
        old_token = utils.get_access_token(client)

        client.users.change_password(old_password, new_password)

        assert_password_incorrect(username, old_password, org)
        assert_password_correct(username, new_password, org)
        utils.assert_access_token(client)
        new_token = utils.get_access_token(client)

        assert old_token != new_token

    def assert_change_password_invalid(client, old_password, new_password):
        with pytest.raises(StatusCodeException) as e:
            client.users.change_password(old_password, new_password)
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=500,
            method="POST",
            url=utils.get_url("changepwd"),
            data={"error": "Unable to update password: Old password does not match."},
        )

    def assert_change_password_fails(client, old_password, new_password):
        with pytest.raises(StatusCodeException) as e:
            client.users.change_password(old_password, new_password)
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=401,
            method="POST",
            url=utils.get_url("changepwd"),
            data={"msg": "Missing Authorization Header"},
        )

    for user_data in data["users"].values():
        client = utils.get_client(user_data["username"], user_data["password"])
        assert_change_password(
            client, user_data["username"], user_data["password"], "password", None
        )
        assert_change_password(
            client, user_data["username"], "password", user_data["password"], None
        )
        assert_change_password_invalid(client, "password", user_data["password"])
        client.logout()

    for org_data in data["organizations"].values():
        for user_data in org_data["users"].values():
            client = utils.get_client_org(
                user_data["username"], user_data["password"], org_data["name"]
            )
            assert_change_password(
                client,
                user_data["username"],
                user_data["password"],
                "password",
                org_data["name"],
            )
            assert_change_password(
                client,
                user_data["username"],
                "password",
                user_data["password"],
                org_data["name"],
            )
            assert_change_password_invalid(client, "password", user_data["password"])
            client.logout()

    client = utils.get_client_sysadmin()
    client.logout()
    assert_change_password_fails(client, "old_password", "new_password")


# TODO:
# test_list_users()
# test_get_user_by_uid()
# test_get_user_by_username()
# test_create_user()
# test_user_update()
# test_user_delete()
# test_user_set_role()
