# Copyright 2024 Google LLC
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

"""Test cases for the firebase_admin.functions module."""

from datetime import datetime, timedelta, timezone
import json
import time
import pytest

import firebase_admin
from firebase_admin import functions
from firebase_admin import _utils
from tests import testutils


_DEFAULT_DATA = {'city': 'Seattle'}
_CLOUD_TASKS_URL = 'https://cloudtasks.googleapis.com/v2/'
_DEFAULT_TASK_PATH = \
    'projects/test-project/locations/us-central1/queues/test-function-name/tasks/test-task-id'
_DEFAULT_REQUEST_URL = \
    _CLOUD_TASKS_URL + 'projects/test-project/locations/us-central1/queues/test-function-name/tasks'
_DEFAULT_TASK_URL = _CLOUD_TASKS_URL + _DEFAULT_TASK_PATH
_DEFAULT_RESPONSE = json.dumps({'name': _DEFAULT_TASK_PATH})

class TestTaskQueue:
    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': 'test-project'})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    def _instrument_functions_service(
        self, app=None, status=200, payload=_DEFAULT_RESPONSE, mounted_url=_CLOUD_TASKS_URL):
        if not app:
            app = firebase_admin.get_app()
        functions_service = functions._get_functions_service(app)
        recorder = []
        functions_service._http_client.session.mount(
            mounted_url,
            testutils.MockAdapter(payload, status, recorder))
        return functions_service, recorder

    def test_task_queue_no_project_id(self):
        def evaluate():
            app = firebase_admin.initialize_app(testutils.MockCredential(), name='no-project-id')
            with pytest.raises(ValueError):
                functions.task_queue('test-function-name', app=app)
        testutils.run_without_project_id(evaluate)

    @pytest.mark.parametrize('function_name', [
        'projects/test-project/locations/us-central1/functions/test-function-name',
        'locations/us-central1/functions/test-function-name',
        'test-function-name',
    ])
    def test_task_queue_function_name(self, function_name):
        queue = functions.task_queue(function_name)
        assert queue._resource.resource_id == 'test-function-name'
        assert queue._resource.project_id == 'test-project'
        assert queue._resource.location_id == 'us-central1'

    def test_task_queue_empty_function_name_error(self):
        with pytest.raises(ValueError) as excinfo:
            functions.task_queue('')
        assert str(excinfo.value) == 'function_name "" must be a non-empty string.'

    def test_task_queue_non_string_function_name_error(self):
        with pytest.raises(ValueError) as excinfo:
            functions.task_queue(1234)
        assert str(excinfo.value) == 'function_name "1234" must be a string.'

    @pytest.mark.parametrize('function_name', [
        '/test',
        'test/',
        'test-project/us-central1/test-function-name',
        'projects/test-project/functions/test-function-name',
        'functions/test-function-name',
    ])
    def test_task_queue_invalid_function_name_error(self, function_name):
        with pytest.raises(ValueError) as excinfo:
            functions.task_queue(function_name)
        assert str(excinfo.value) == 'Invalid resource name format.'

    def test_task_queue_extension_id(self):
        queue = functions.task_queue("test-function-name", "test-extension-id")
        assert queue._resource.resource_id == 'ext-test-extension-id-test-function-name'
        assert queue._resource.project_id == 'test-project'
        assert queue._resource.location_id == 'us-central1'

    def test_task_queue_empty_extension_id_error(self):
        with pytest.raises(ValueError) as excinfo:
            functions.task_queue('test-function-name', '')
        assert str(excinfo.value) == 'extension_id "" must be a non-empty string.'

    def test_task_queue_non_string_extension_id_error(self):
        with pytest.raises(ValueError) as excinfo:
            functions.task_queue('test-function-name', 1234)
        assert str(excinfo.value) == 'extension_id "1234" must be a string.'


    def test_task_enqueue(self):
        _, recorder = self._instrument_functions_service()
        queue = functions.task_queue('test-function-name')
        task_id = queue.enqueue(_DEFAULT_DATA)
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == _DEFAULT_REQUEST_URL
        assert recorder[0].headers['Content-Type'] == 'application/json'
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'
        expected_metrics_header = _utils.get_metrics_header() + ' mock-cred-metric-tag'
        assert recorder[0].headers['x-goog-api-client'] == expected_metrics_header
        assert task_id == 'test-task-id'

        task = json.loads(recorder[0].body.decode())['task']
        assert task['httpRequest']['oidcToken'] == {'serviceAccountEmail': 'mock-email'}
        assert task['httpRequest']['headers'] == {'Content-Type': 'application/json'}

    def test_task_enqueue_with_extension(self):
        resource_name = (
            'projects/test-project/locations/us-central1/queues/'
            'ext-test-extension-id-test-function-name/tasks'
        )
        extension_response = json.dumps({'name': resource_name + '/test-task-id'})
        _, recorder = self._instrument_functions_service(payload=extension_response)
        queue = functions.task_queue('test-function-name', 'test-extension-id')
        task_id = queue.enqueue(_DEFAULT_DATA)
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == _CLOUD_TASKS_URL + resource_name
        assert recorder[0].headers['Content-Type'] == 'application/json'
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'
        expected_metrics_header = _utils.get_metrics_header() + ' mock-cred-metric-tag'
        assert recorder[0].headers['x-goog-api-client'] == expected_metrics_header
        assert task_id == 'test-task-id'

        task = json.loads(recorder[0].body.decode())['task']
        assert task['httpRequest']['oidcToken'] == {'serviceAccountEmail': 'mock-email'}
        assert task['httpRequest']['headers'] == {'Content-Type': 'application/json'}

    def test_task_enqueue_compute_engine(self):
        app = firebase_admin.initialize_app(
            testutils.MockComputeEngineCredential(),
            options={'projectId': 'test-project'},
            name='test-project-gce')
        _, recorder = self._instrument_functions_service(app)
        queue = functions.task_queue('test-function-name', app=app)
        task_id = queue.enqueue(_DEFAULT_DATA)
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == _DEFAULT_REQUEST_URL
        assert recorder[0].headers['Content-Type'] == 'application/json'
        assert recorder[0].headers['Authorization'] == 'Bearer mock-compute-engine-token'
        expected_metrics_header = _utils.get_metrics_header() + ' mock-gce-cred-metric-tag'
        assert recorder[0].headers['x-goog-api-client'] == expected_metrics_header
        assert task_id == 'test-task-id'

        task = json.loads(recorder[0].body.decode())['task']
        assert task['httpRequest']['oidcToken'] == {'serviceAccountEmail': 'mock-gce-email'}
        assert task['httpRequest']['headers'] == {'Content-Type': 'application/json'}

    def test_task_enqueue_with_extension_compute_engine(self):
        resource_name = (
            'projects/test-project/locations/us-central1/queues/'
            'ext-test-extension-id-test-function-name/tasks'
        )
        extension_response = json.dumps({'name': resource_name + '/test-task-id'})
        app = firebase_admin.initialize_app(
            testutils.MockComputeEngineCredential(),
            options={'projectId': 'test-project'},
            name='test-project-gce-extensions')
        _, recorder = self._instrument_functions_service(app, payload=extension_response)
        queue = functions.task_queue('test-function-name', 'test-extension-id', app)
        task_id = queue.enqueue(_DEFAULT_DATA)
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == _CLOUD_TASKS_URL + resource_name
        assert recorder[0].headers['Content-Type'] == 'application/json'
        assert recorder[0].headers['Authorization'] == 'Bearer mock-compute-engine-token'
        expected_metrics_header = _utils.get_metrics_header() + ' mock-gce-cred-metric-tag'
        assert recorder[0].headers['x-goog-api-client'] == expected_metrics_header
        assert task_id == 'test-task-id'

        task = json.loads(recorder[0].body.decode())['task']
        assert 'oidcToken' not in task['httpRequest']
        assert task['httpRequest']['headers'] == {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer mock-compute-engine-token'}

    def test_task_delete(self):
        _, recorder = self._instrument_functions_service()
        queue = functions.task_queue('test-function-name')
        queue.delete('test-task-id')
        assert len(recorder) == 1
        assert recorder[0].method == 'DELETE'
        assert recorder[0].url == _DEFAULT_TASK_URL
        expected_metrics_header = _utils.get_metrics_header() + ' mock-cred-metric-tag'
        assert recorder[0].headers['x-goog-api-client'] == expected_metrics_header

    def test_task_enqueue_with_emulator_host(self, monkeypatch):
        emulator_host = 'localhost:8124'
        emulator_url = f'http://{emulator_host}/'
        request_url = emulator_url + _DEFAULT_TASK_PATH.replace('/tasks/test-task-id', '/tasks')

        monkeypatch.setenv('CLOUD_TASKS_EMULATOR_HOST', emulator_host)
        app = firebase_admin.initialize_app(
            _utils.EmulatorAdminCredentials(), {'projectId': 'test-project'}, name='emulator-app')

        expected_task_name = (
            '/projects/test-project/locations/us-central1'
            '/queues/test-function-name/tasks/test-task-id'
        )
        expected_response = json.dumps({'task': {'name': expected_task_name}})
        _, recorder = self._instrument_functions_service(
            app, payload=expected_response, mounted_url=emulator_url)

        queue = functions.task_queue('test-function-name', app=app)
        task_id = queue.enqueue(_DEFAULT_DATA)

        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == request_url
        assert recorder[0].headers['Content-Type'] == 'application/json'

        task = json.loads(recorder[0].body.decode())['task']
        assert task['httpRequest']['oidcToken'] == {
            'serviceAccountEmail': 'emulated-service-acct@email.com'
        }
        assert task_id == 'test-task-id'

    def test_task_enqueue_without_emulator_host_error(self, monkeypatch):
        app = firebase_admin.initialize_app(
            _utils.EmulatorAdminCredentials(),
            {'projectId': 'test-project'}, name='no-emulator-app')

        _, recorder = self._instrument_functions_service(app)
        monkeypatch.delenv('CLOUD_TASKS_EMULATOR_HOST', raising=False)
        queue = functions.task_queue('test-function-name', app=app)
        with pytest.raises(ValueError) as excinfo:
            queue.enqueue(_DEFAULT_DATA)
        assert "Failed to determine service account" in str(excinfo.value)
        assert len(recorder) == 0

    def test_get_emulator_url_invalid_format(self, monkeypatch):
        monkeypatch.setenv('CLOUD_TASKS_EMULATOR_HOST', 'http://localhost:8124')
        app = firebase_admin.initialize_app(
            testutils.MockCredential(), {'projectId': 'test-project'}, name='invalid-host-app')
        with pytest.raises(ValueError) as excinfo:
            functions.task_queue('test-function-name', app=app)
        assert 'Invalid CLOUD_TASKS_EMULATOR_HOST' in str(excinfo.value)

class TestTaskQueueOptions:

    _DEFAULT_TASK_OPTS = {'schedule_delay_seconds': None, 'schedule_time': None, \
                          'dispatch_deadline_seconds': None, 'task_id': None, 'headers': None}

    non_alphanumeric_chars = [
        ',', '.', '?', '!', ':', ';', "'", '"', '(', ')', '[', ']', '{', '}',
        '@', '&', '*', '+', '=', '$', '%', '#', '~', '\\', '/', '|', '^',
        '\t', '\n', '\r', '\f', '\v', '\0', '\a', '\b',
        'é', 'ç', 'ö', '❤️', '€', '¥', '£', '←', '→', '↑', '↓', 'π', 'Ω', 'ß'
    ]

    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': 'test-project'})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    def _instrument_functions_service(self, app=None, status=200, payload=_DEFAULT_RESPONSE):
        if not app:
            app = firebase_admin.get_app()
        functions_service = functions._get_functions_service(app)
        recorder = []
        functions_service._http_client.session.mount(
            _CLOUD_TASKS_URL,
            testutils.MockAdapter(payload, status, recorder))
        return functions_service, recorder

    def test_task_options_delay_seconds(self):
        _, recorder = self._instrument_functions_service()
        enqueue_time = datetime.now(timezone.utc)
        expected_schedule_time = enqueue_time + timedelta(seconds=100)
        task_opts_params = {
            'schedule_delay_seconds': 100,
            'schedule_time': None,
            'dispatch_deadline_seconds': 200,
            'task_id': 'test-task-id',
            'headers': {'x-test-header': 'test-header-value'},
            'uri': 'https://google.com'
        }
        queue = functions.task_queue('test-function-name')
        task_opts = functions.TaskOptions(**task_opts_params)
        queue.enqueue(_DEFAULT_DATA, task_opts)

        assert len(recorder) == 1
        task = json.loads(recorder[0].body.decode())['task']

        task_schedule_time = datetime.fromisoformat(task['scheduleTime'].replace('Z', '+00:00'))
        delta = abs(task_schedule_time - expected_schedule_time)
        assert delta <= timedelta(seconds=1)

        assert task['dispatchDeadline'] == '200s'
        assert task['httpRequest']['headers']['x-test-header'] == 'test-header-value'
        assert task['httpRequest']['url'] in ['http://google.com', 'https://google.com']
        assert task['name'] == _DEFAULT_TASK_PATH

    def test_task_options_utc_time(self):
        _, recorder = self._instrument_functions_service()
        enqueue_time = datetime.now(timezone.utc)
        expected_schedule_time = enqueue_time + timedelta(seconds=100)
        task_opts_params = {
            'schedule_delay_seconds': None,
            'schedule_time': expected_schedule_time,
            'dispatch_deadline_seconds': 200,
            'task_id': 'test-task-id',
            'headers': {'x-test-header': 'test-header-value'},
            'uri': 'http://google.com'
        }
        queue = functions.task_queue('test-function-name')
        task_opts = functions.TaskOptions(**task_opts_params)
        queue.enqueue(_DEFAULT_DATA, task_opts)

        assert len(recorder) == 1
        task = json.loads(recorder[0].body.decode())['task']

        task_schedule_time = datetime.fromisoformat(task['scheduleTime'].replace('Z', '+00:00'))
        assert task_schedule_time == expected_schedule_time

        assert task['dispatchDeadline'] == '200s'
        assert task['httpRequest']['headers']['x-test-header'] == 'test-header-value'
        assert task['httpRequest']['url'] in ['http://google.com', 'https://google.com']
        assert task['name'] == _DEFAULT_TASK_PATH

    def test_schedule_set_twice_error(self):
        _, recorder = self._instrument_functions_service()
        opts = functions.TaskOptions(
            schedule_delay_seconds=100, schedule_time=datetime.now(timezone.utc))
        queue = functions.task_queue('test-function-name')
        with pytest.raises(ValueError) as excinfo:
            queue.enqueue(_DEFAULT_DATA, opts)
        assert len(recorder) == 0
        assert str(excinfo.value) == \
            'Both schedule_delay_seconds and schedule_time cannot be set at the same time.'


    @pytest.mark.parametrize('schedule_time', [
        time.time(),
        str(datetime.now(timezone.utc)),
        datetime.now(timezone.utc).isoformat(),
        datetime.now(timezone.utc).isoformat() + 'Z',
        '', ' '
    ])
    def test_invalid_schedule_time_error(self, schedule_time):
        _, recorder = self._instrument_functions_service()
        opts = functions.TaskOptions(schedule_time=schedule_time)
        queue = functions.task_queue('test-function-name')
        with pytest.raises(ValueError) as excinfo:
            queue.enqueue(_DEFAULT_DATA, opts)
        assert len(recorder) == 0
        assert str(excinfo.value) == 'schedule_time should be UTC datetime.'


    @pytest.mark.parametrize('schedule_delay_seconds', [
        -1, '100', '-1', '', ' ', -1.23, 1.23
    ])
    def test_invalid_schedule_delay_seconds_error(self, schedule_delay_seconds):
        _, recorder = self._instrument_functions_service()
        opts = functions.TaskOptions(schedule_delay_seconds=schedule_delay_seconds)
        queue = functions.task_queue('test-function-name')
        with pytest.raises(ValueError) as excinfo:
            queue.enqueue(_DEFAULT_DATA, opts)
        assert len(recorder) == 0
        assert str(excinfo.value) == 'schedule_delay_seconds should be positive int.'


    @pytest.mark.parametrize('dispatch_deadline_seconds', [
        14, 1801, -15, -1800, 0, '100', '-1', '', ' ', -1.23, 1.23,
    ])
    def test_invalid_dispatch_deadline_seconds_error(self, dispatch_deadline_seconds):
        _, recorder = self._instrument_functions_service()
        opts = functions.TaskOptions(dispatch_deadline_seconds=dispatch_deadline_seconds)
        queue = functions.task_queue('test-function-name')
        with pytest.raises(ValueError) as excinfo:
            queue.enqueue(_DEFAULT_DATA, opts)
        assert len(recorder) == 0
        assert str(excinfo.value) == \
            'dispatch_deadline_seconds should be int in the range of 15s to 1800s (30 mins).'


    @pytest.mark.parametrize('task_id', [
        '', ' ', 'task/1', 'task.1', 'a'*501, *non_alphanumeric_chars
    ])
    def test_invalid_task_id_error(self, task_id):
        _, recorder = self._instrument_functions_service()
        opts = functions.TaskOptions(task_id=task_id)
        queue = functions.task_queue('test-function-name')
        with pytest.raises(ValueError) as excinfo:
            queue.enqueue(_DEFAULT_DATA, opts)
        assert len(recorder) == 0
        assert str(excinfo.value) == (
            'task_id can contain only letters ([A-Za-z]), numbers ([0-9]), '
            'hyphens (-), or underscores (_). The maximum length is 500 characters.'
        )

    @pytest.mark.parametrize('uri', [
        '', ' ', 'a', 'foo', 'image.jpg', [], {}, True, 'google.com', 'www.google.com'
    ])
    def test_invalid_uri_error(self, uri):
        _, recorder = self._instrument_functions_service()
        opts = functions.TaskOptions(uri=uri)
        queue = functions.task_queue('test-function-name')
        with pytest.raises(ValueError) as excinfo:
            queue.enqueue(_DEFAULT_DATA, opts)
        assert len(recorder) == 0
        assert str(excinfo.value) == \
            'uri must be a valid RFC3986 URI string using the https or http schema.'
