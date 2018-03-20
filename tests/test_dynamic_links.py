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
from tests import get_link_stats_vals

MOCK_SHORT_URL = 'https://fake1.app.goo.gl/uQWc'
MOCK_GET_STATS_RESPONSE = testutils.resource('get_link_stats.json')

MOCK_CREDENTIAL = credentials.Certificate(
    testutils.resource_filename('service_account.json'))

INVALID_STRINGS = [None, '', 0, 1, True, False, list(), tuple(), dict(), object()]
INVALID_NON_NEGATIVE_NUMS = [None, '', 'foo', -1, True, False, list(), tuple(), dict(), object()]
INVALID_LISTS = [None, 'foo', 0, 1, True, False, dict(), object()]


class DynamicLinksFixture(object):
    def __init__(self, name=None):
        if name:
            self.app = firebase_admin.get_app(name)
        else:
            self.app = None
        self.links_service = dynamic_links._get_link_service(self.app)

    def _instrument_dynamic_links(self, payload, status=200):
        request_url = dynamic_links._LINKS_BASE_URL
        recorder = []
        self.links_service._client.session.mount(request_url,
                                                 testutils.MockAdapter(payload, status, recorder))
        return self.links_service, recorder


@pytest.fixture(params=[None, 'testDLApp'], ids=['DefaultApp', 'CustomApp'])
def dynamic_links_test(request):
    """Returns a DynamicLinksFixture instance.

    Instances returned by this fixture are parameterized to use either the defult App instance,
    or a custom App instance named 'testDLApp'. Due to this parameterization, each test case that
    depends on this fixture will get executed twice (as two test cases); once with the default
    App, and once with the custom App.
    """
    return DynamicLinksFixture(request.param)

def setup_module():
    firebase_admin.initialize_app(testutils.MockCredential())
    firebase_admin.initialize_app(testutils.MockCredential(), name='testDLApp')

def teardown_module():
    firebase_admin.delete_app(firebase_admin.get_app())
    firebase_admin.delete_app(firebase_admin.get_app('testDLApp'))


class TestGetStats(object):
    def test_get_stats(self, dynamic_links_test):
        _, recorder = dynamic_links_test._instrument_dynamic_links(
            payload=MOCK_GET_STATS_RESPONSE)
        options = dynamic_links.StatOptions(duration_days=9)
        link_stats = dynamic_links.get_link_stats(
            MOCK_SHORT_URL, options, app=dynamic_links_test.app)
        assert recorder[0].url.startswith("https://firebasedynamiclinks.googleapis.com")
        assert (recorder[0].path_url ==
                "/v1/https%3A%2F%2Ffake1.app.goo.gl%2FuQWc/linkStats?durationDays=9")
        assert isinstance(link_stats, dynamic_links.LinkStats)
        for event_stat in link_stats.event_stats:
            assert isinstance(event_stat, dynamic_links.EventStats)

        compared_event_stats = get_link_stats_vals.comparison
        assert len(compared_event_stats) == len(link_stats.event_stats)
        for (direct, returned) in zip(compared_event_stats, link_stats.event_stats):
            assert returned.platform == direct['platform']
            assert returned.event == direct['event']
            assert returned.count == direct['count']

    def test_get_stats_error(self, dynamic_links_test):
        dynamic_links_test._instrument_dynamic_links(payload=MOCK_GET_STATS_RESPONSE,
                                                     status=500)
        options = dynamic_links.StatOptions(duration_days=9)
        with pytest.raises(requests.exceptions.HTTPError) as excinfo:
            dynamic_links.get_link_stats(MOCK_SHORT_URL, options, app=dynamic_links_test.app)
        assert excinfo.value.response.status_code == 500

    @pytest.mark.parametrize('invalid_url', ['google.com'] + INVALID_STRINGS)
    def test_get_stats_invalid_url(self, dynamic_links_test, invalid_url):
        options = dynamic_links.StatOptions(duration_days=9)
        with pytest.raises(ValueError) as excinfo:
            dynamic_links.get_link_stats(invalid_url, options, app=dynamic_links_test.app)
        assert 'short_link must be a string and begin with "https://".' in str(excinfo.value)

    @pytest.mark.parametrize('invalid_options', INVALID_STRINGS)
    def test_get_stats_invalid_options(self, dynamic_links_test, invalid_options):
        with pytest.raises(ValueError) as excinfo:
            dynamic_links.get_link_stats(
                MOCK_SHORT_URL, invalid_options, app=dynamic_links_test.app)
        assert 'stat_options must be of type StatOptions.' in str(excinfo.value)

    @pytest.mark.parametrize('invalid_duration', [0] + INVALID_NON_NEGATIVE_NUMS)
    def test_get_stats_invalid_duration_days(self, invalid_duration):
        with pytest.raises(ValueError) as excinfo:
            dynamic_links.StatOptions(duration_days=invalid_duration)
        assert 'duration_days' in str(excinfo.value)
        assert 'must be positive int' in str(excinfo.value)


class TestEventStats(object):
    @pytest.mark.parametrize('platform', dynamic_links.EventStats._platforms.keys())
    def test_valid_platform_values(self, platform):
        event_stats = dynamic_links.EventStats(
            platform=dynamic_links.EventStats._platforms[platform],
            event=dynamic_links.EVENT_TYPE_CLICK,
            count=1)
        assert event_stats.platform == dynamic_links.EventStats._platforms[platform]

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['unrecognized'])
    def test_invalid_platform_values(self, arg):
        with pytest.raises(ValueError) as excinfo:
            dynamic_links.EventStats(
                platform=arg,
                event=dynamic_links.EVENT_TYPE_CLICK,
                count=1)
        assert 'not recognized' in str(excinfo.value)

    @pytest.mark.parametrize('arg', dynamic_links.EventStats._platforms.keys())
    def test_raw_platform_values_invalid(self, arg):
        with pytest.raises(ValueError) as excinfo:
            dynamic_links.EventStats(
                platform=arg,
                event=dynamic_links.EVENT_TYPE_CLICK,
                count=1)
        assert 'Raw string' in str(excinfo.value)

    @pytest.mark.parametrize('event', dynamic_links.EventStats._event_types.keys())
    def test_valid_event_values(self, event):
        event_stats = dynamic_links.EventStats(
            platform=dynamic_links.PLATFORM_ANDROID,
            event=dynamic_links.EventStats._event_types[event],
            count=1)
        assert event_stats.event == dynamic_links.EventStats._event_types[event]

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['unrecognized'])
    def test_invalid_event_values(self, arg):
        with pytest.raises(ValueError) as excinfo:
            dynamic_links.EventStats(
                platform=dynamic_links.PLATFORM_ANDROID,
                event=arg,
                count=1)
        assert 'not recognized' in str(excinfo.value)

    @pytest.mark.parametrize('arg', dynamic_links.EventStats._event_types.keys())
    def test_raw_event_values_invalid(self, arg):
        with pytest.raises(ValueError) as excinfo:
            dynamic_links.EventStats(
                platform=dynamic_links.PLATFORM_ANDROID,
                event=arg,
                count=1)
        assert 'Raw string' in str(excinfo.value)

    @pytest.mark.parametrize('count', [1, 123, 1234])
    def test_valid_count_values(self, count):
        event_stats = dynamic_links.EventStats(
            platform=dynamic_links.PLATFORM_ANDROID,
            event=dynamic_links.EVENT_TYPE_CLICK,
            count=count)
        assert event_stats.count == count

    @pytest.mark.parametrize('arg', INVALID_NON_NEGATIVE_NUMS)
    def test_invalid_count_values(self, arg):
        with pytest.raises(ValueError) as excinfo:
            dynamic_links.EventStats(
                platform=dynamic_links.PLATFORM_ANDROID,
                event=dynamic_links.EVENT_TYPE_CLICK,
                count=arg)
        assert 'must be a non negative int' in str(excinfo.value)


class TestLinkStats(object):
    @pytest.mark.parametrize('arg', INVALID_LISTS)
    def test_invalid_event_stats_list(self, arg):
        with pytest.raises(ValueError) as excinfo:
            dynamic_links.LinkStats(arg)
        assert'Must be a list or tuple' in str(excinfo.value)

    @pytest.mark.parametrize('arg', [list([1, 2]), list('asdf'), tuple([1, 2])])
    def test_empty_event_stats_list(self, arg):
        with pytest.raises(ValueError) as excinfo:
            dynamic_links.LinkStats(arg)
        assert 'elements of event stats must be "EventStats"' in str(excinfo.value)
