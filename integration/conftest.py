# Copyright 2017 Google Inc.
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

"""pytest configuration and global fixtures for integration tests."""
import json

import pytest

import firebase_admin
from firebase_admin import credentials


def pytest_addoption(parser):
    parser.addoption(
        '--cert', action='store', help='Service account certificate file for integration tests.')
    parser.addoption(
        '--apikey', action='store', help='API key file for integration tests.')

def _get_cert_path(request):
    cert = request.config.getoption('--cert')
    if cert:
        return cert
    raise ValueError('Service account certificate not specified. Make sure to specify the '
                     '"--cert" command-line option.')

def integration_conf(request):
    cert_path = _get_cert_path(request)
    with open(cert_path) as cert:
        project_id = json.load(cert).get('project_id')
    if not project_id:
        raise ValueError('Failed to determine project ID from service account certificate.')
    return credentials.Certificate(cert_path), project_id

@pytest.fixture(scope='session')
def project_id(request):
    _, project_id = integration_conf(request)
    return project_id

@pytest.fixture(autouse=True, scope='session')
def default_app(request):
    """Initializes the default Firebase App instance used for all integration tests.

    This fixture is attached to the session scope, which ensures that it runs only once during
    a test session. It is also marked as autouse, and therefore runs automatically without
    test cases having to call it explicitly.
    """
    cred, project_id = integration_conf(request)
    ops = {
        'databaseURL' : 'https://{0}.firebaseio.com'.format(project_id),
        'storageBucket' : '{0}.appspot.com'.format(project_id)
    }
    return firebase_admin.initialize_app(cred, ops)

@pytest.fixture(scope='session')
def api_key(request):
    path = request.config.getoption('--apikey')
    if not path:
        raise ValueError('API key file not specified. Make sure to specify the "--apikey" '
                         'command-line option.')
    with open(path) as keyfile:
        return keyfile.read().strip()
 