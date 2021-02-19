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

import random
import sys
from pathlib import Path
from urllib.parse import urljoin

import pytest

import conftest
import utils

# isort: off

sys.path.append(str(Path(__file__).resolve().parent.parent))
import securicad.enterprise.aws_import_cli as aws
from securicad import enterprise

# isort: on


def test_example():
    def get_org_name(client):
        orgs = client.organizations.list_organizations()
        while True:
            org_name = f"org-{random.randint(1000, 9999)}"
            for org in orgs:
                if org.name.lower() == org_name.lower():
                    break
            else:
                return org_name

    # Fetch AWS data
    aws_data = aws.import_cli(config=conftest.AWS_IMPORT_CONFIG)

    # Create authenticated client
    client = enterprise.client(
        base_url=conftest.BASE_URL,
        backend_url=conftest.BACKEND_URL,
        username=conftest.ADMIN_USERNAME,
        password=conftest.ADMIN_PASSWORD,
        cacert=False,
    )

    # Create organization and project
    org = client.organizations.create_organization(get_org_name(client))
    project = client.projects.create_project("Example Project", organization=org)

    # Generate model from AWS data
    model_info = client.parsers.generate_aws_model(
        project, name="Example Model", cli_files=[aws_data]
    )

    # Set high value assets in model
    high_value_assets = [
        {
            "metaconcept": "S3Bucket",
            "attackstep": "ReadObject",
            "consequence": 7,
        }
    ]

    model = model_info.get_model()
    model.set_high_value_assets(high_value_assets=high_value_assets)
    client.models.save(project, model)

    # Create scenario and get initial simulation
    scenario = client.scenarios.create_scenario(
        project, model_info, name="Example Scenario"
    )
    simulation = client.simulations.get_simulation_by_name(
        scenario, name="Initial simulation"
    )

    # Get results
    results = simulation.get_results()
    assert results["report_url"] == urljoin(
        conftest.BASE_URL,
        f"project/{project.pid}/scenario/{scenario.tid}/report/{simulation.simid}",
    )

    # Results
    org.delete()
