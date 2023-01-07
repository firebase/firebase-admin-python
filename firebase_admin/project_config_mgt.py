import re
import threading
from firebase_admin.multi_factor_config_mgt import MultiFactorConfig, TotpProviderConfig, ProviderConfig 

import requests

import firebase_admin
from firebase_admin import auth
from firebase_admin import _auth_utils
from firebase_admin import _http_client
from firebase_admin import _utils

_PROJECT_MGT_ATTRIBUTE = '_project_mgt'

def auth_for_project(project_id, app=None):
    """Gets an Auth Client instance scoped to the given project ID.

    Args:
        project_id: A project ID string.
        app: An App instance (optional).

    Returns:
        auth.Client: An ``auth.Client`` object.

    Raises:
        ValueError: If the project ID is None, empty or not a string.
    """
    project_mgt_service = _get_project_mgt_service(app)
    return project_mgt_service.auth_for_project(project_id)

def _get_project_mgt_service(app):
    return _utils.get_app_service(app, _PROJECT_MGT_ATTRIBUTE, _ProjectManagementService)

class Project:
    """Represents a project in an application.
    """

    def __init__(self, data):
        print(data)
        if not isinstance(data, dict):
            raise ValueError('Invalid data argument in Project constructor: {0}'.format(data))
        if not 'name' in data:
            raise ValueError('Project response missing required keys.')

        self._data = data
    
    @property
    def mfa(self):
        data = self._data.get('multiFactorConfig')
        if data:
            return MultiFactorConfig(data)
        else:
            return None

class _ProjectManagementService:
    """Firebase project management service."""

    PROJECT_MGT_URL = 'https://identitytoolkit.googleapis.com/v2/projects'

    def __init__(self, app):
        credential = app.credential.get_credential()
        version_header = 'Python/Admin/{0}'.format(firebase_admin.__version__)
        base_url = '{0}/{1}'.format(self.PROJECT_MGT_URL, app.project_id)
        self.app = app
        self.client = _http_client.JsonHttpClient(
            credential=credential, base_url=base_url, headers={'X-Client-Version': version_header})
        self.project_clients = {}
        self.lock = threading.RLock()

    def auth_for_project(self, project_id):
        """Gets an Auth Client instance scoped to the given project ID."""
        if not isinstance(project_id, str) or not project_id:
            raise ValueError(
                'Invalid project ID: {0}. Project ID must be a non-empty string.'.format(project_id))

        with self.lock:
            if project_id in self.project_clients:
                return self.project_clients[project_id]

            client = auth.Client(self.app, project_id=project_id)
            self.project_clients[project_id] = client
            return  client
    
    def get_project(self, project_id):
        """Gets the project corresponding to the given ``project_id``."""
        if not isinstance(project_id, str) or not project_id:
            raise ValueError(
                'Invalid project ID: {0}. Project ID must be a non-empty string.'.format(project_id))

        try:
            body = self.client.body('get', ''.format(project_id))
        except requests.exceptions.RequestException as error:
            raise _auth_utils.handle_auth_backend_error(error)
        else:
            return Project(body)
    
    def update_project(
            self, project_id, mfa=None):
        """Updates the specified project with the given parameters."""
        if not isinstance(project_id, str) or not project_id:
            raise ValueError('Project ID must be a non-empty string.')

        payload = {}
        if mfa is not None:
            payload['multiFactorConfig'] = _auth_utils.validate_mfa_config(mfa)

        if not payload:
            raise ValueError('At least one parameter must be specified for update.')

        url = '/projects/{0}'.format(project_id)
        update_mask = ','.join(_auth_utils.build_update_mask(payload))
        params = 'updateMask={0}'.format(update_mask)
        try:
            body = self.client.body('patch', url, json=payload, params=params)
        except requests.exceptions.RequestException as error:
            raise _auth_utils.handle_auth_backend_error(error)
        else:
            return Project(body)


