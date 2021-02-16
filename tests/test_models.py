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
# test_list_models()
# test_get_model_by_mid()
# test_get_model_by_name()
# test_save()
# test_save_as()
# test_upload_scad_model()
# test_upload_aws_model()
# test_modelinfo_update()
# test_modelinfo_delete()
# test_modelinfo_lock()
# test_modelinfo_release()
# test_modelinfo_get_scad()
# test_modelinfo_get_dict()
# test_modelinfo_get_model()
