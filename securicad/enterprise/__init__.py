# Copyright 2020 Foreseeti AB
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

from enum import Enum
from securicad.enterprise.client import Client

__version__ = "0.0.1"
__author__ = "Foreseeti AB"


class Role(Enum):
    USER = ["user"]
    PROJECT_CREATOR = ["user", "project_creator"]
    ADMIN = ["user", "project_creator", "admin"]
    SYSADMIN = ["user", "project_creator", "admin", "system_admin"]


class AccessLevel(Enum):
    GUEST = 100
    USER = 180
    OWNER = 250


def client(url, username, password, org=None, cacert=None):
    return Client(url, username, password, org, cacert)
