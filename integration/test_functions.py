# Copyright 2024 Google Inc.
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

"""Integration tests for firebase_admin.functions module."""

import os
import pytest

import firebase_admin
from firebase_admin import functions
from firebase_admin import _utils
from integration import conftest


_DEFAULT_DATA = {'data': {'city': 'Seattle'}}
def integration_conf(request):
    host_override = os.environ.get('CLOUD_TASKS_EMULATOR_HOST')
    if host_override:
        return _utils.EmulatorAdminCredentials(), 'fake-project-id'

    return conftest.integration_conf(request)

@pytest.fixture(scope='module')
def app(request):
    cred, project_id = integration_conf(request)
    return firebase_admin.initialize_app(
        cred, options={'projectId': project_id}, name='integration-functions')

@pytest.fixture(scope='module', autouse=True)
def default_app(request):
    # Overwrites the default_app fixture in conftest.py.
    # This test suite should not use the default app. Use the app fixture instead.
    pass


class TestFunctions:

    _TEST_FUNCTIONS_PARAMS = [
        {'function_name': 'function-name'},
        {'function_name': 'projects/test-project/locations/test-location/functions/function-name'},
        {'function_name': 'function-name', 'extension_id': 'extension-id'},
        {
            'function_name': \
                'projects/test-project/locations/test-location/functions/function-name',
            'extension_id': 'extension-id'
        }
    ]

    @pytest.mark.parametrize('task_queue_params', _TEST_FUNCTIONS_PARAMS)
    def test_task_queue(self, task_queue_params, app):
        assert app.name == 'integration-functions'
        queue = functions.task_queue(**task_queue_params, app=app)
        assert queue is not None
        assert callable(queue.enqueue)
        assert callable(queue.delete)

    def test_task_enqueue(self, app):
        queue = functions.task_queue('testTaskQueue', app=app)
        task_id = queue.enqueue(_DEFAULT_DATA)
        assert task_id is not None

    @pytest.mark.skipif(
        os.environ.get('CLOUD_TASKS_EMULATOR_HOST') is not None,
        reason="Skipping test_task_delete against emulator due to bug in firebase-tools"
    )
    def test_task_delete(self, app):
        # Skip this test against the emulator since tasks can't be delayed there to verify deletion
        # See: https://github.com/firebase/firebase-tools/issues/8254
        task_options = functions.TaskOptions(schedule_delay_seconds=60)
        queue = functions.task_queue('testTaskQueue', app=app)  
        task_id = queue.enqueue(_DEFAULT_DATA, task_options)
        assert task_id is not None
        queue.delete(task_id)
        # We don't have a way to check the contents of the queue so we check that the deleted
        # task is not found using the delete method again.
        with pytest.raises(firebase_admin.exceptions.NotFoundError):
            queue.delete(task_id)
