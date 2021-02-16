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


def test_init(data):
    def assert_init(username, password):
        client = utils.get_client(username, password)
        utils.assert_access_token(client)
        client.logout()

    def assert_init_org(username, password, org):
        client = utils.get_client_org(username, password, org)
        utils.assert_access_token(client)
        client.logout()

    def assert_init_invalid(username, password):
        with pytest.raises(StatusCodeException) as e:
            utils.get_client(username, password)
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=401,
            method="POST",
            url=utils.get_url("auth/login"),
            data={"error": "Invalid login"},
        )

    def assert_init_org_invalid(username, password, org):
        with pytest.raises(StatusCodeException) as e:
            utils.get_client_org(username, password, org)
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=401,
            method="POST",
            url=utils.get_url("auth/login"),
            data={"error": "Invalid login"},
        )

    for user_data in data["users"].values():
        assert_init(user_data["username"], user_data["password"])
        assert_init_org(user_data["username"], user_data["password"], None)

    for org_data in data["organizations"].values():
        for user_data in org_data["users"].values():
            assert_init_org(
                user_data["username"], user_data["password"], org_data["name"]
            )

    assert_init_invalid("invalid", "invalid")
    assert_init_org_invalid("invalid", "invalid", None)
    assert_init_org_invalid("invalid", "invalid", "invalid")


def test_login(data):
    def assert_login(client, username, password):
        utils.assert_access_token(client)
        old_token = utils.get_access_token(client)

        client.login(username, password)

        utils.assert_access_token(client)
        new_token = utils.get_access_token(client)

        assert old_token != new_token

    def assert_logout_login(client, username, password):
        utils.assert_access_token(client)
        old_token = utils.get_access_token(client)

        client.logout()

        utils.assert_not_access_token(client)

        client.login(username, password)

        utils.assert_access_token(client)
        new_token = utils.get_access_token(client)

        assert old_token != new_token

    def assert_login_org(client, username, password, org):
        utils.assert_access_token(client)
        old_token = utils.get_access_token(client)

        client.login(username, password, org)

        utils.assert_access_token(client)
        new_token = utils.get_access_token(client)

        assert old_token != new_token

    def assert_logout_login_org(client, username, password, org):
        utils.assert_access_token(client)
        old_token = utils.get_access_token(client)

        client.logout()

        utils.assert_not_access_token(client)

        client.login(username, password, org)

        utils.assert_access_token(client)
        new_token = utils.get_access_token(client)

        assert old_token != new_token

    def assert_login_invalid(client, username, password):
        with pytest.raises(StatusCodeException) as e:
            client.login(username, password)
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=401,
            method="POST",
            url=utils.get_url("auth/login"),
            data={"error": "Invalid login"},
        )

    def assert_login_org_invalid(client, username, password, org):
        with pytest.raises(StatusCodeException) as e:
            client.login(username, password, org)
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=401,
            method="POST",
            url=utils.get_url("auth/login"),
            data={"error": "Invalid login"},
        )

    for user_data in data["users"].values():
        client = utils.get_client_sysadmin()
        assert_login(client, user_data["username"], user_data["password"])
        client.logout()

        client = utils.get_client_sysadmin()
        assert_logout_login(client, user_data["username"], user_data["password"])
        client.logout()

        client = utils.get_client_sysadmin()
        assert_login_org(client, user_data["username"], user_data["password"], None)
        client.logout()

        client = utils.get_client_sysadmin()
        assert_logout_login_org(
            client, user_data["username"], user_data["password"], None
        )
        client.logout()

    for org_data in data["organizations"].values():
        for user_data in org_data["users"].values():
            client = utils.get_client_sysadmin()
            assert_login_org(
                client, user_data["username"], user_data["password"], org_data["name"]
            )
            client.logout()

            client = utils.get_client_sysadmin()
            assert_logout_login_org(
                client, user_data["username"], user_data["password"], org_data["name"]
            )
            client.logout()

    client = utils.get_client_sysadmin()
    assert_login_invalid(client, "invalid", "invalid")
    client.logout()

    client = utils.get_client_sysadmin()
    assert_login_org_invalid(client, "invalid", "invalid", None)
    client.logout()

    client = utils.get_client_sysadmin()
    assert_login_org_invalid(client, "invalid", "invalid", "invalid")
    client.logout()


def test_logout(data):
    def assert_logout(client):
        utils.assert_access_token(client)
        client.logout()
        utils.assert_not_access_token(client)

    def assert_logout_fails(client):
        with pytest.raises(StatusCodeException) as e:
            client.logout()
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=401,
            method="POST",
            url=utils.get_url("auth/logout"),
            data={"msg": "Missing Authorization Header"},
        )

    for user_data in data["users"].values():
        client = utils.get_client(user_data["username"], user_data["password"])
        assert_logout(client)

        client = utils.get_client_org(
            user_data["username"], user_data["password"], None
        )
        assert_logout(client)

    for org_data in data["organizations"].values():
        for user_data in org_data["users"].values():
            client = utils.get_client_org(
                user_data["username"], user_data["password"], org_data["name"]
            )
            assert_logout(client)

    client = utils.get_client_sysadmin()
    client.logout()
    assert_logout_fails(client)


def test_refresh(data):
    def assert_refresh(client):
        utils.assert_access_token(client)
        old_token = utils.get_access_token(client)

        client.refresh()

        utils.assert_access_token(client)
        new_token = utils.get_access_token(client)

        assert old_token != new_token

    def assert_refresh_fails(client):
        with pytest.raises(StatusCodeException) as e:
            client.refresh()
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=401,
            method="POST",
            url=utils.get_url("auth/refresh"),
            data={"msg": "Missing Authorization Header"},
        )

    for user_data in data["users"].values():
        client = utils.get_client(user_data["username"], user_data["password"])
        assert_refresh(client)
        client.logout()

        client = utils.get_client_org(
            user_data["username"], user_data["password"], None
        )
        assert_refresh(client)
        client.logout()

    for org_data in data["organizations"].values():
        for user_data in org_data["users"].values():
            client = utils.get_client_org(
                user_data["username"], user_data["password"], org_data["name"]
            )
            assert_refresh(client)
            client.logout()

    client = utils.get_client_sysadmin()
    client.logout()
    assert_refresh_fails(client)
