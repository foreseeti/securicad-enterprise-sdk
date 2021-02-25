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

from securicad.enterprise.client import Client
from securicad.enterprise.models import ModelInfo
from securicad.enterprise.organizations import Organization
from securicad.enterprise.projects import AccessLevel, Project
from securicad.enterprise.scenarios import Scenario
from securicad.enterprise.simulations import Simulation
from securicad.enterprise.users import Role, User

__version__ = "0.1.0"
__author__ = "Foreseeti AB"


def client(*args, **kwargs) -> Client:
    return Client(*args, **kwargs)
