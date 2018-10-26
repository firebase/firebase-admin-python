# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Firebase Project Management module.

This module enables management of resources in Firebase projects, such as
Android and iOS Apps.
"""

import requests
import six

from firebase_admin import _http_client
from firebase_admin import _utils


_PROJECT_MANAGEMENT_SERVICE_URL = 'https://firebase.googleapis.com'
_PROJECT_MANAGEMENT_ATTRIBUTE = '_project_management'


def _get_project_management_service(app):
    return _utils.get_app_service(
        app, _PROJECT_MANAGEMENT_ATTRIBUTE, _ProjectManagementService)


class ApiCallError(Exception):
    """An error arisen from using the Firebase Project Management Service."""

    def __init__(self, message, error):
        Exception.__init__(self, message)
        self.detail = error


class _ProjectManagementService(object):
  pass
