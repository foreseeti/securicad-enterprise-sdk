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
from securicad.enterprise import AccessLevel, Organization
from securicad.enterprise.exceptions import StatusCodeException

# isort: on


def test_list_orgs(data):
    def assert_list_orgs(client):
        orgs = client.organizations.list_organizations()
        expected_len = len(data["organizations"])
        actual_len = len(orgs)
        assert actual_len == expected_len, f"len(orgs) {actual_len} != {expected_len}"

        for org_data in data["organizations"].values():
            for org in orgs:
                if org.name == org_data["name"]:
                    utils.assert_org_data(org, org_data)
                    break
            else:
                assert False, f"Organization \"{org_data['name']}\" not found"

    def assert_list_orgs_fails(client):
        with pytest.raises(StatusCodeException) as e:
            client.organizations.list_organizations()
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=401,
            method="GET",
            url=utils.get_url("organization/all"),
            data={"msg": "Missing Authorization Header"},
        )

    def assert_list_orgs_forbidden(client):
        with pytest.raises(StatusCodeException) as e:
            client.organizations.list_organizations()
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=403,
            method="GET",
            url=utils.get_url("organization/all"),
            data={
                "error": "You are not authorized to access this resource: system_admin required."
            },
        )

    for user_data in data["users"].values():
        client = utils.get_client(user_data["username"], user_data["password"])
        assert_list_orgs(client)
        client.logout()

    for org_data in data["organizations"].values():
        for user_data in org_data["users"].values():
            client = utils.get_client_org(
                user_data["username"], user_data["password"], org_data["name"]
            )
            assert_list_orgs_forbidden(client)
            client.logout()

    client = utils.get_client_sysadmin()
    client.logout()
    assert_list_orgs_fails(client)


def test_get_org_by_tag(data):
    def assert_get_org_by_tag(client, org_data):
        org = client.organizations.get_organization_by_tag(org_data["tag"])
        utils.assert_org_data(org, org_data)

    def assert_get_org_by_tag_invalid(client, tag):
        with pytest.raises(StatusCodeException) as e:
            client.organizations.get_organization_by_tag(tag)
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=503,
            method="GET",
            url=utils.get_url(f"organization/{tag}"),
            data={"error": "Failed to retrieve organization info"},
        )

    def assert_get_org_by_tag_fails(client, tag):
        with pytest.raises(StatusCodeException) as e:
            client.organizations.get_organization_by_tag(tag)
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=401,
            method="GET",
            url=utils.get_url(f"organization/{tag}"),
            data={"msg": "Missing Authorization Header"},
        )

    def assert_get_org_by_tag_forbidden(client, tag):
        with pytest.raises(StatusCodeException) as e:
            client.organizations.get_organization_by_tag(tag)
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=403,
            method="GET",
            url=utils.get_url(f"organization/{tag}"),
            data={
                "error": "You are not authorized to access this resource: system_admin required."
            },
        )

    for user_data in data["users"].values():
        client = utils.get_client(user_data["username"], user_data["password"])
        for org in data["organizations"].values():
            assert_get_org_by_tag(client, org)
        assert_get_org_by_tag_invalid(client, "invalid")
        client.logout()

    for org_data in data["organizations"].values():
        for user_data in org_data["users"].values():
            client = utils.get_client_org(
                user_data["username"], user_data["password"], org_data["name"]
            )
            for org in data["organizations"].values():
                assert_get_org_by_tag_forbidden(client, org["tag"])
            assert_get_org_by_tag_forbidden(client, "invalid")
            client.logout()

    client = utils.get_client_sysadmin()
    client.logout()
    assert_get_org_by_tag_fails(client, "invalid")


def test_get_org_by_name(data):
    def assert_get_org_by_name(client, org_data):
        org = client.organizations.get_organization_by_name(org_data["name"])
        utils.assert_org_data(org, org_data)

    def assert_get_org_by_name_invalid(client, name):
        with pytest.raises(ValueError) as e:
            client.organizations.get_organization_by_name(name)
        assert str(e.value) == f"Invalid organization {name}"

    def assert_get_org_by_name_fails(client, name):
        with pytest.raises(StatusCodeException) as e:
            client.organizations.get_organization_by_name(name)
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=401,
            method="GET",
            url=utils.get_url("organization/all"),
            data={"msg": "Missing Authorization Header"},
        )

    def assert_get_org_by_name_forbidden(client, name):
        with pytest.raises(StatusCodeException) as e:
            client.organizations.get_organization_by_name(name)
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=403,
            method="GET",
            url=utils.get_url("organization/all"),
            data={
                "error": "You are not authorized to access this resource: system_admin required."
            },
        )

    for user_data in data["users"].values():
        client = utils.get_client(user_data["username"], user_data["password"])
        for org in data["organizations"].values():
            assert_get_org_by_name(client, org)
        assert_get_org_by_name_invalid(client, "invalid")
        client.logout()

    for org_data in data["organizations"].values():
        for user_data in org_data["users"].values():
            client = utils.get_client_org(
                user_data["username"], user_data["password"], org_data["name"]
            )
            for org in data["organizations"].values():
                assert_get_org_by_name_forbidden(client, org["name"])
            assert_get_org_by_name_forbidden(client, "invalid")
            client.logout()

    client = utils.get_client_sysadmin()
    client.logout()
    assert_get_org_by_name_fails(client, "invalid")


def test_create_org(data):
    def assert_create_org(client, name):
        org = client.organizations.create_organization(name)
        assert (
            org.name == name
        ), f'Unexpected organization name "{org.name}" != "{name}"'
        org.delete()

    def assert_create_org_invalid(client, name):
        with pytest.raises(StatusCodeException) as e:
            client.organizations.create_organization(name)
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=500,
            method="PUT",
            url=utils.get_url("organization"),
            data={"error": "Failed to add organization"},
        )

    def assert_create_org_fails(client, name):
        with pytest.raises(StatusCodeException) as e:
            client.organizations.create_organization(name)
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=401,
            method="PUT",
            url=utils.get_url("organization"),
            data={"msg": "Missing Authorization Header"},
        )

    def assert_create_org_forbidden(client, name):
        with pytest.raises(StatusCodeException) as e:
            client.organizations.create_organization(name)
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=403,
            method="PUT",
            url=utils.get_url("organization"),
            data={
                "error": "You are not authorized to access this resource: system_admin required."
            },
        )

    for user_data in data["users"].values():
        client = utils.get_client(user_data["username"], user_data["password"])
        assert_create_org(client, "org3")
        for org in data["organizations"].values():
            assert_create_org_invalid(client, org["name"])
        client.logout()

    for org_data in data["organizations"].values():
        for user_data in org_data["users"].values():
            client = utils.get_client_org(
                user_data["username"], user_data["password"], org_data["name"]
            )
            assert_create_org_forbidden(client, "org3")
            for org in data["organizations"].values():
                assert_create_org_forbidden(client, org["name"])
            client.logout()

    client = utils.get_client_sysadmin()
    client.logout()
    assert_create_org_fails(client, "org3")


def test_org_update(data):
    def assert_org_update(client, tag, old_name, new_name):
        org = client.organizations.get_organization_by_tag(tag)
        utils.assert_org_data(org, {"tag": tag, "name": old_name})

        org.update(name=new_name)
        utils.assert_org_data(org, {"tag": tag, "name": new_name})

        org = client.organizations.get_organization_by_tag(tag)
        utils.assert_org_data(org, {"tag": tag, "name": new_name})

    def assert_org_update_invalid(org, new_name):
        with pytest.raises(StatusCodeException) as e:
            org.update(name=new_name)
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=503,
            method="POST",
            url=utils.get_url("organization"),
            data={"error": "Failed to update organization"},
        )

    def assert_org_update_fails(org, new_name):
        with pytest.raises(StatusCodeException) as e:
            org.update(name=new_name)
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=401,
            method="POST",
            url=utils.get_url("organization"),
            data={"msg": "Missing Authorization Header"},
        )

    def assert_org_update_forbidden(org, new_name):
        with pytest.raises(StatusCodeException) as e:
            org.update(name=new_name)
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=403,
            method="POST",
            url=utils.get_url("organization"),
            data={
                "error": "You are not authorized to access this resource: system_admin required."
            },
        )

    for user_data in data["users"].values():
        client = utils.get_client(user_data["username"], user_data["password"])
        for org in data["organizations"].values():
            org_ = Organization(client, org["tag"], org["name"])
            assert_org_update(client, org["tag"], org["name"], "org3")
            assert_org_update(client, org["tag"], "org3", org["name"])
            for org_name in data["organizations"]:
                if org_name == org["name"]:
                    assert_org_update(client, org["tag"], org["name"], org_name)
                else:
                    assert_org_update_invalid(org_, org_name)
        client.logout()

    for org_data in data["organizations"].values():
        for user_data in org_data["users"].values():
            client = utils.get_client_org(
                user_data["username"], user_data["password"], org_data["name"]
            )
            for org in data["organizations"].values():
                org_ = Organization(client, org["tag"], org["name"])
                assert_org_update_forbidden(org_, "org3")
                for org_name in data["organizations"]:
                    assert_org_update_forbidden(org_, org_name)
            client.logout()

    client = utils.get_client_sysadmin()
    client.logout()
    for org in data["organizations"].values():
        org_ = Organization(client, org["tag"], org["name"])
        assert_org_update_fails(org_, "org3")

    client = utils.get_client_sysadmin()
    org_ = client.organizations.create_organization("org3")
    org_.delete()
    assert_org_update_invalid(org_, "org4")
    client.logout()


def test_org_delete(data):
    def assert_org(client, tag, name):
        org = client.organizations.get_organization_by_tag(tag)
        utils.assert_org_data(org, {"tag": tag, "name": name})

    def assert_not_org(client, tag):
        with pytest.raises(StatusCodeException) as e:
            client.organizations.get_organization_by_tag(tag)
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=503,
            method="GET",
            url=utils.get_url(f"organization/{tag}"),
            data={"error": "Failed to retrieve organization info"},
        )

    def assert_org_delete(client, name):
        org = client.organizations.create_organization(name)
        assert_org(client, org.tag, org.name)

        org.delete()
        assert_not_org(client, org.tag)

    def assert_org_delete_invalid(org):
        with pytest.raises(StatusCodeException) as e:
            org.delete()
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=503,
            method="DELETE",
            url=utils.get_url("organization"),
            data={"error": "Organization not found"},
        )

    def assert_org_delete_fails(org):
        with pytest.raises(StatusCodeException) as e:
            org.delete()
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=401,
            method="DELETE",
            url=utils.get_url("organization"),
            data={"msg": "Missing Authorization Header"},
        )

    def assert_org_delete_forbidden(org):
        with pytest.raises(StatusCodeException) as e:
            org.delete()
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=403,
            method="DELETE",
            url=utils.get_url("organization"),
            data={
                "error": "You are not authorized to access this resource: system_admin required."
            },
        )

    for user_data in data["users"].values():
        client = utils.get_client(user_data["username"], user_data["password"])
        assert_org_delete(client, "org3")
        client.logout()

    for org_data in data["organizations"].values():
        for user_data in org_data["users"].values():
            client = utils.get_client_org(
                user_data["username"], user_data["password"], org_data["name"]
            )
            for org in data["organizations"].values():
                org_ = Organization(client, org["tag"], org["name"])
                assert_org_delete_forbidden(org_)
            client.logout()

    client = utils.get_client_sysadmin()
    client.logout()
    for org in data["organizations"].values():
        org_ = Organization(client, org["tag"], org["name"])
        assert_org_delete_fails(org_)

    client = utils.get_client_sysadmin()
    org_ = client.organizations.create_organization("org3")
    org_.delete()
    assert_org_delete_invalid(org_)
    client.logout()


def test_org_list_users(data):
    def assert_org_list_users(org):
        users = org.list_users()
        expected_len = len(data["organizations"][org.name]["users"])
        actual_len = len(users)
        assert actual_len == expected_len, f"len(users) {actual_len} != {expected_len}"

        for user_data in data["organizations"][org.name]["users"].values():
            for user in users:
                if user.username == user_data["username"]:
                    utils.assert_user_data(user, user_data)
                    break
            else:
                assert (
                    False
                ), f"User \"{user_data['name']}\" not found in organization \"{org.name}\""

    def assert_org_list_users_invalid(org):
        with pytest.raises(StatusCodeException) as e:
            org.list_users()
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=503,
            method="GET",
            url=utils.get_url(f"organization/{org.tag}"),
            data={"error": "Failed to retrieve organization info"},
        )

    def assert_org_list_users_fails(org):
        with pytest.raises(StatusCodeException) as e:
            org.list_users()
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=401,
            method="GET",
            url=utils.get_url(f"organization/{org.tag}"),
            data={"msg": "Missing Authorization Header"},
        )

    def assert_org_list_users_forbidden(org):
        with pytest.raises(StatusCodeException) as e:
            org.list_users()
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=403,
            method="GET",
            url=utils.get_url(f"organization/{org.tag}"),
            data={
                "error": "You are not authorized to access this resource: system_admin required."
            },
        )

    for user_data in data["users"].values():
        client = utils.get_client(user_data["username"], user_data["password"])
        for org in data["organizations"].values():
            org_ = Organization(client, org["tag"], org["name"])
            assert_org_list_users(org_)
        client.logout()

    for org_data in data["organizations"].values():
        for user_data in org_data["users"].values():
            client = utils.get_client_org(
                user_data["username"], user_data["password"], org_data["name"]
            )
            for org in data["organizations"].values():
                org_ = Organization(client, org["tag"], org["name"])
                assert_org_list_users_forbidden(org_)
            client.logout()

    client = utils.get_client_sysadmin()
    client.logout()
    for org in data["organizations"].values():
        org_ = Organization(client, org["tag"], org["name"])
        assert_org_list_users_fails(org_)

    client = utils.get_client_sysadmin()
    org_ = client.organizations.create_organization("org3")
    org_.delete()
    assert_org_list_users_invalid(org_)
    client.logout()


def test_org_list_projects(data):
    def assert_org_list_projects(org):
        projects = org.list_projects()
        expected_len = len(data["organizations"][org.name]["projects"])
        actual_len = len(projects)
        assert (
            actual_len == expected_len
        ), f"len(projects) {actual_len} != {expected_len}"

        for project_data in data["organizations"][org.name]["projects"].values():
            for project in projects:
                if project.name == project_data["name"]:
                    utils.assert_project_data(project, project_data, AccessLevel.ADMIN)
                    break
            else:
                assert (
                    False
                ), f"Project \"{project_data['name']}\" not found in organization \"{org.name}\""

    def assert_org_list_projects_invalid(org):
        with pytest.raises(StatusCodeException) as e:
            org.list_projects()
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=503,
            method="GET",
            url=utils.get_url(f"organization/{org.tag}"),
            data={"error": "Failed to retrieve organization info"},
        )

    def assert_org_list_projects_fails(org):
        with pytest.raises(StatusCodeException) as e:
            org.list_projects()
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=401,
            method="GET",
            url=utils.get_url(f"organization/{org.tag}"),
            data={"msg": "Missing Authorization Header"},
        )

    def assert_org_list_projects_forbidden(org):
        with pytest.raises(StatusCodeException) as e:
            org.list_projects()
        utils.assert_status_code_exception(
            exception=e.value,
            status_code=403,
            method="GET",
            url=utils.get_url(f"organization/{org.tag}"),
            data={
                "error": "You are not authorized to access this resource: system_admin required."
            },
        )

    for user_data in data["users"].values():
        client = utils.get_client(user_data["username"], user_data["password"])
        for org in data["organizations"].values():
            org_ = Organization(client, org["tag"], org["name"])
            assert_org_list_projects(org_)
        client.logout()

    for org_data in data["organizations"].values():
        for user_data in org_data["users"].values():
            client = utils.get_client_org(
                user_data["username"], user_data["password"], org_data["name"]
            )
            for org in data["organizations"].values():
                org_ = Organization(client, org["tag"], org["name"])
                assert_org_list_projects_forbidden(org_)
            client.logout()

    client = utils.get_client_sysadmin()
    client.logout()
    for org in data["organizations"].values():
        org_ = Organization(client, org["tag"], org["name"])
        assert_org_list_projects_fails(org_)

    client = utils.get_client_sysadmin()
    org_ = client.organizations.create_organization("org3")
    org_.delete()
    assert_org_list_projects_invalid(org_)
    client.logout()
