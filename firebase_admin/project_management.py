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

This module enables management of resources in Firebase projects, such as Android and iOS Apps.
"""

import threading

import requests
import six

from firebase_admin import _http_client
from firebase_admin import _utils


_PROJECT_MANAGEMENT_ATTRIBUTE = '_project_management'


def _get_project_management_service(app):
    return _utils.get_app_service(app, _PROJECT_MANAGEMENT_ATTRIBUTE, _ProjectManagementService)


def android_app(app_id, app=None):
    """Obtains a reference to an Android App in the associated Firebase Project.

    Args:
        app_id: The App ID that identifies this Android App.
        app: An App instance (optional).

    Returns:
        AndroidApp: An ``AndroidApp`` instance.
    """
    return AndroidApp(app_id=app_id, service=_get_project_management_service(app))


def list_android_apps(app=None):
    """Lists all Android Apps in the associated Firebase Project.

    Args:
        app: An App instance (optional).

    Returns:
        list: a list of ``AndroidApp`` instances referring to each Android App in the Firebase
            Project.
    """
    return _get_project_management_service(app).list_android_apps()


def create_android_app(package_name, display_name=None, app=None):
    """Creates a new Android App in the associated Firebase Project.

    Args:
        package_name: The package name of the Android App to be created.
        display_name: A nickname for this Android App (optional).
        app: An App instance (optional).

    Returns:
        AndroidApp: An ``AndroidApp`` instance that is a reference to the newly created App.
    """
    return _get_project_management_service(app).create_android_app(package_name, display_name)


def _check_is_string(obj, field_name):
    if isinstance(obj, six.string_types):
        return obj
    raise ValueError('{0} must be a string.'.format(field_name))


def _check_is_string_or_none(obj, field_name):
    if obj is None:
        return None
    return _check_is_string(obj, field_name)


def _check_is_nonempty_string(obj, field_name):
    if isinstance(obj, six.string_types) and obj:
        return obj
    raise ValueError('{0} must be a non-empty string.'.format(field_name))


class ApiCallError(Exception):
    """An error encountered while interacting with the Firebase Project Management Service."""

    def __init__(self, message, error):
        Exception.__init__(self, message)
        self.detail = error


class PollingError(Exception):
    """An error encountered during the polling of an App's creation status."""

    def __init__(self, message):
        Exception.__init__(self, message)


class AndroidApp(object):
    """A reference to an Android App within a Firebase Project.

    Please use the module-level function ``android_app(app_id)`` to obtain instances of this class
    instead of instantiating it directly.
    """

    def __init__(self, app_id, service):
        self._app_id = app_id
        self._service = service

    @property
    def app_id(self):
        return self._app_id

    def get_metadata(self):
        """Retrieves detailed information about this Android App.

        Note: this method makes an RPC.

        Returns:
            AndroidAppMetadata: An ``AndroidAppMetadata`` instance.

        Raises:
            ApiCallError: If an error occurs while communicating with the Firebase Project
                Management Service.
        """
        return self._service.get_android_app_metadata(self._app_id)


class AppMetadata(object):
    """Detailed information about a Firebase App."""

    def __init__(self, name, app_id, display_name, project_id):
        self._name = _check_is_nonempty_string(name, 'name')
        self._app_id = _check_is_nonempty_string(app_id, 'app_id')
        self._display_name = _check_is_string(display_name, 'display_name')
        self._project_id = _check_is_nonempty_string(project_id, 'project_id')

    @property
    def name(self):
        """The fully qualified resource name of this Android App."""
        return self._name

    @property
    def app_id(self):
        """The globally unique, Firebase-assigned identifier of this Android App.

        This ID is unique even across Apps of different platforms, such as iOS Apps.
        """
        return self._app_id

    @property
    def display_name(self):
        """The user-assigned display name of this Android App."""
        return self._display_name

    @property
    def project_id(self):
        """The permanent, globally unique, user-assigned ID of the parent Firebase Project."""
        return self._project_id


class AndroidAppMetadata(AppMetadata):
    """Android-specific information about an Android Firebase App."""

    def __init__(self, name, app_id, display_name, project_id, package_name):
        super(AndroidAppMetadata, self).__init__(name, app_id, display_name, project_id)
        self._package_name = _check_is_nonempty_string(package_name, 'package_name')

    @property
    def package_name(self):
        """The canonical package name of this Android App as it would appear in the Play Store."""
        return self._package_name


class _ProjectManagementService(object):
    """Provides methods for interacting with the Firebase Project Management Service."""

    BASE_URL = 'https://firebase.googleapis.com'
    MAXIMUM_LIST_APPS_PAGE_SIZE = 1
    ERROR_CODES = {
        401: 'Request not authorized.',
        403: 'Client does not have sufficient privileges.',
        404: 'Failed to find the resource.',
        409: 'The resource already exists.',
        429: 'Request throttled out by the backend server.',
        500: 'Internal server error.',
        503: 'Backend servers are over capacity. Try again later.'
    }

    def __init__(self, app):
        project_id = app.project_id
        if not project_id:
            raise ValueError(
                'Project ID is required to access the Firebase Project Management Service. Either '
                'set the projectId option, or use service account credentials. Alternatively, set '
                'the GOOGLE_CLOUD_PROJECT environment variable.')
        self._project_id = project_id
        self._client = _http_client.JsonHttpClient(
            credential=app.credential.get_credential(),
            base_url=_ProjectManagementService.BASE_URL)
        self._timeout = app.options.get('httpTimeout')

    def get_android_app_metadata(self, app_id):
        """Retrieves detailed information about an Android App."""
        _check_is_nonempty_string(app_id, 'app_id')
        path = '/v1beta1/projects/-/androidApps/{0}'.format(app_id)
        response = self._make_request('get', path, app_id, 'App ID')
        return AndroidAppMetadata(
            name=response['name'],
            app_id=response['appId'],
            display_name=response['displayName'],
            project_id=response['projectId'],
            package_name=response['packageName'])

    def list_android_apps(self):
        """Lists all the Android Apps within the Firebase Project."""
        path = '/v1beta1/projects/{0}/androidApps?pageSize={1}'.format(
            self._project_id, _ProjectManagementService.MAXIMUM_LIST_APPS_PAGE_SIZE)
        response = self._make_request('get', path, self._project_id, 'Project ID')
        apps_list = []
        while True:
            apps = response.get('apps')
            if not apps:
                break
            apps_list.extend(AndroidApp(app_id=app['appId'], service=self) for app in apps)
            next_page_token = response.get('nextPageToken')
            if not next_page_token:
                break
            # Retrieve the next page of Apps.
            path = '/v1beta1/projects/{0}/androidApps?pageToken={1}&pageSize={2}'.format(
                self._project_id,
                next_page_token,
                _ProjectManagementService.MAXIMUM_LIST_APPS_PAGE_SIZE)
            response = self._make_request('get', path, self._project_id, 'Project ID')
        return apps_list

    def create_android_app(self, package_name, display_name=None):
        """Creates an Android App."""
        _check_is_string_or_none(display_name, 'display_name')
        path = '/v1beta1/projects/{0}/androidApps'.format(self._project_id)
        request_body = {'displayName': display_name, 'packageName': package_name}
        response = self._make_request('post', path, package_name, 'Package name', json=request_body)
        operation_name = response['name']
        poller = _OperationPoller(operation_name, self._timeout, self._client)
        polling_thread = threading.Thread(target=poller.run)
        polling_thread.start()
        polling_thread.join()
        poller_response = poller.response
        if poller_response:
            return AndroidApp(app_id=poller_response['appId'], service=self)
        if poller.error:
            raise ApiCallError(
                self._extract_message(operation_name, 'Operation name', poller.error), poller.error)

    def _make_request(self, method, url, resource_identifier, resource_identifier_label, json=None):
        try:
            return self._client.body(method=method, url=url, json=json, timeout=self._timeout)
        except requests.exceptions.RequestException as error:
            raise ApiCallError(
                self._extract_message(resource_identifier, resource_identifier_label, error), error)

    def _extract_message(self, identifier, identifier_label, error):
        if not isinstance(error, requests.exceptions.RequestException) or error.response is None:
            return str(error)
        status = error.response.status_code
        message = _ProjectManagementService.ERROR_CODES.get(status)
        if message:
            return '{0} "{1}": {2}'.format(identifier_label, identifier, message)
        return '{0} "{1}": Error {2}.'.format(identifier_label, identifier, status)


class _OperationPoller(object):
    """Polls the Long-Running Operation repeatedly until it is done, with exponential backoff.

    Currently, this class is somewhat redundant, since all functionality operates synchronously;
    however, in the future, if we offer an asynchronous API, this class can become useful.

    Args:
        operation_name: The Long-Running Operation name to poll.
        rpc_timeout: The number of seconds to wait for the polling RPC to complete.
        client: A JsonHttpClient to make the RPC calls with.
    """

    MAXIMUM_POLLING_ATTEMPTS = 8
    POLL_BASE_WAIT_TIME_SECONDS = 0.5
    POLL_EXPONENTIAL_BACKOFF_FACTOR = 1.5

    def __init__(self, operation_name, rpc_timeout, client):
        self._operation_name = operation_name
        self._rpc_timeout = rpc_timeout
        self._client = client
        self._current_attempt = 0
        self._done = False
        self._waiting_thread_cv = threading.Condition()
        self._error = None
        self._response = None

    @property
    def current_wait_time(self):
        delay_factor = pow(_OperationPoller.POLL_EXPONENTIAL_BACKOFF_FACTOR, self._current_attempt)
        return _OperationPoller.POLL_BASE_WAIT_TIME_SECONDS * delay_factor

    @property
    def error(self):
        return self._error

    @property
    def response(self):
        return self._response

    def run(self):
        with self._waiting_thread_cv:
            # Repeatedly poll (with exponential backoff) until the Operation is done.
            while not self._done:
                # Note that it is impossible for poll_and_notify to execute its body earlier than
                # the wait() call below because we still have the CV's lock.
                timer = threading.Timer(
                    interval=self.current_wait_time, function=self.poll_and_notify)
                timer.start()
                self._waiting_thread_cv.wait()

    def poll_and_notify(self):
        with self._waiting_thread_cv:
            try:
                self._current_attempt += 1
                path = '/v1/{0}'.format(self._operation_name)
                poll_response = self._client.body('get', url=path, timeout=self._rpc_timeout)
                done = poll_response.get('done')
                # If either the Operation is done or we have exceeded our retry limit, we set one of
                # _response or _error, and set _done to True.
                if done or self._current_attempt >= _OperationPoller.MAXIMUM_POLLING_ATTEMPTS:
                    if done:
                        response = poll_response.get('response')
                        if response:
                            self._response = response
                        else:
                            self._error = PollingError('Operation terminated in an error.')
                    else:
                        self._error = PollingError('Polling deadline exceeded.')
                    self._done = True
            except requests.exceptions.RequestException as error:
                # If any attempt results in an RPC error, we stop the retries.
                self._error = error  # pylint: disable=redefined-variable-type
                self._done = True
            # Other Exceptions are ignored and polling will be retried.
            finally:
                # We must always reawaken the thread that calls run().
                self._waiting_thread_cv.notify()