# Copyright 2026 Google Inc.
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

"""Integration tests for firebase_admin.dataconnect module."""

import pytest

import firebase_admin
from firebase_admin import dataconnect
from tests import testutils

BASE_CONFIG = dataconnect.ConnectorConfig(
    service_id="starterproject",
    location="us-east4",
    connector="my_connector",
)


@pytest.fixture(scope='module', autouse=True)
def default_app():
    # Overwrites the default_app fixture in conftest.py.
    # This test suite does not use the default app.
    pass


class TestDataConnectServiceIntegration:

    def setup_method(self):
        self.cred = testutils.MockCredential()
        self.app1 = firebase_admin.initialize_app(self.cred, name="integ_app1")
        self.app2 = firebase_admin.initialize_app(self.cred, name="integ_app2")

        self.config1 = BASE_CONFIG
        self.config2 = dataconnect.ConnectorConfig(
            service_id="service2", location="us-east4", connector="conn2"
        )
        self.config1_copy = dataconnect.ConnectorConfig(
            service_id="starterproject", location="us-east4", connector="my_connector"
        )

    def teardown_method(self, method):
        del method
        for app in [getattr(self, 'app1', None), getattr(self, 'app2', None)]:
            if app:
                try:
                    firebase_admin.delete_app(app)
                except ValueError:
                    pass

    def test_overall_client_retrieval_and_caching(self):
        client1a = dataconnect.client(self.config1, app=self.app1)
        client1b = dataconnect.client(self.config1_copy, app=self.app1)
        client2 = dataconnect.client(self.config2, app=self.app1)

        assert isinstance(client1a, dataconnect.DataConnect)
        assert client1a.app is self.app1
        assert client1a.config is self.config1

        # Same config
        assert client1b is client1a

        # Different config
        assert isinstance(client2, dataconnect.DataConnect)
        assert client2.app is self.app1
        assert client2.config is self.config2
        assert client2 is not client1a

        # Different app
        client1_app2 = dataconnect.client(self.config1, app=self.app2)

        assert isinstance(client1_app2, dataconnect.DataConnect)
        assert client1_app2.app is self.app2
        assert client1_app2.config is self.config1
        assert client1_app2 is not client1a
