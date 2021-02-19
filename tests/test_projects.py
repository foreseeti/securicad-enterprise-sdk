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

# TODO:
# test_list_projects()
# test_get_project_by_pid()
# test_get_project_by_name()
# test_create_project()
# test_project_update()
# test_project_delete()
# test_project_list_users()
# test_project_add_user()
# test_project_remove_user()
# test_project_get_access_level()
# test_project_set_access_level()
# test_project_list_models()
# test_project_import_models()
# test_project_list_scenarios()
