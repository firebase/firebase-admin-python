# Copyright 2021 Google Inc.
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

"""Firebase App Check module.
"""

try:
    from google.firebase import appcheck_v1beta
    existing = globals().keys()
    for key, value in appcheck_v1beta.__dict__.items():
        if not key.startswith('_') and key not in existing:
            globals()[key] = value
except ImportError:
    raise ImportError('Failed to import the Firebase App Check library for Python. Make sure '
                      'to install the "google-cloud-firestore" module.')

from firebase_admin import _token_gen
from firebase_admin import _utils


_FAC_ATTRIBUTE = '_appcheck'


def _get_fac_service(app=None):
    return _utils.get_app_service(app, _FAC_ATTRIBUTE, _AppCheckClient.from_app)

def create_token(app_id, app=None):
    project_id = _get_fac_service(app).project_id()
    token = _get_fac_service(app).token_generator().create_custom_token_fac(app_id)
    payload = {}
    payload['app'] = 'projects/{project_number}/apps/{app_id}'.format(
        project_number=project_id, app_id=app_id)
    payload['custom_token'] = token
    return _get_fac_service(app).get().exchange_custom_token(payload)


class _AppCheckClient:
    """Holds a Firebase App Check client instance."""

    def __init__(self, credentials, project, token_generator):
        self._project = project
        self._client = appcheck_v1beta.services.token_exchange_service.TokenExchangeServiceClient(
            credentials=credentials, transport='rest')
        self._token_generator = token_generator

    def get(self):
        return self._client

    def project_id(self):
        return self._project

    def token_generator(self):
        return self._token_generator

    @classmethod
    def from_app(cls, app):
        """Creates a new _FirestoreClient for the specified app."""
        credentials = app.credential.get_credential()
        project = app.project_id
        token_generator = _token_gen.TokenGenerator(app, http_client=None)
        if not project:
            raise ValueError(
                'Project ID is required to access Firestore. Either set the projectId option, '
                'or use service account credentials. Alternatively, set the GOOGLE_CLOUD_PROJECT '
                'environment variable.')
        return _AppCheckClient(credentials, project, token_generator)
