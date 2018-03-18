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


"""Test cases for the firebase_admin.dynamic_links module."""

import pytest
import requests

import firebase_admin
from firebase_admin import dynamic_links
from firebase_admin import credentials

from tests import testutils

MOCK_GET_STATS_RESPONSE = testutils.resource('get_link_stats.json')

MOCK_CREDENTIAL = credentials.Certificate(
    testutils.resource_filename('service_account.json'))

INVALID_STRINGS = [None, '', 0, 1, True, False, list(), tuple(), dict()]
INVALID_BOOLS = [None, '', 'foo', 0, 1, list(), tuple(), dict()]
INVALID_DICTS = [None, 'foo', 0, 1, True, False, list(), tuple()]
INVALID_POSITIVE_NUMS = [None, 'foo', 0, -1, True, False, list(), tuple(), dict()]

class DLFixture(object):
    def __init__(self, name=None):
        if name:
            self.app = firebase_admin.get_app(name)
        else:
            self.app = None

    def _instrument_dynamic_links(self, payload, status=200):
        links_service = dynamic_links._get_link_service(self.app)
        request_url = dynamic_links._LINKS_BASE_URL
        recorder = []
        links_service._client.session.mount(request_url,
                                            testutils.MockAdapter(payload, status, recorder))
        return links_service, recorder


@pytest.fixture(params=[None, 'testDLApp'], ids=['DefaultApp', 'CustomApp'])
def dltest(request):
    """Returns a DLFixture instance.

    Instances returned by this fixture are parameterized to use either the defult App instance,
    or a custom App instance named 'testDLApp'. Due to this parameterization, each test case that
    depends on this fixture will get executed twice (as two test cases); once with the default
    App, and once with the custom App.
    """
    return DLFixture(request.param)

def setup_module():
    firebase_admin.initialize_app(testutils.MockCredential())
    firebase_admin.initialize_app(testutils.MockCredential(), name='testDLApp')

def teardown_module():
    firebase_admin.delete_app(firebase_admin.get_app())
    firebase_admin.delete_app(firebase_admin.get_app('testDLApp'))



class TestGetStats(object):
    def test_get_stats(self, dltest):
        dltest._instrument_dynamic_links(payload=MOCK_GET_STATS_RESPONSE)
        options = dynamic_links.StatOptions(duration_days=9)
        link_stats = dynamic_links.get_link_stats('mock', options, app=dltest.app)
        assert(link_stats.event_stats[0] ==
               dynamic_links.EventStats(platform=u'ANDROID', event=u'CLICK', count=123))
        assert len(link_stats.event_stats) == 7

    def test_get_stats_error(self, dltest):
        dltest._instrument_dynamic_links(payload=MOCK_GET_STATS_RESPONSE,
                                         status=500)
        options = dynamic_links.StatOptions(duration_days=9)
        with pytest.raises(requests.exceptions.HTTPError) as excinfo:
            dynamic_links.get_link_stats('mock', options, app=dltest.app)
