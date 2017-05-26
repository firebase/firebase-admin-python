import json

import pytest

import firebase_admin
from firebase_admin import credentials


def pytest_addoption(parser):
    parser.addoption(
        '--cert', action='store', help='Service account certificate file for integration tests.')

def _get_cert_path(request):
    cert = request.config.getoption('--cert')
    if cert:
        return cert
    raise ValueError('Service account certificate not specified. Make sure to specify the '
                     '"--cert" command-line option.')

@pytest.fixture(autouse=True, scope='session')
def default_app(request):
    cert_path = _get_cert_path(request)
    with open(cert_path) as cert:
        project_id = json.load(cert).get('project_id')
    if not project_id:
        raise ValueError('Failed to determine project ID from service account certificate.')
    cred = credentials.Certificate(cert_path)
    ops = {'dbURL' : 'https://{0}.firebaseio.com'.format(project_id)}
    return firebase_admin.initialize_app(cred, ops)


