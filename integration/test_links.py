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

"""Integration tests for firebase_admin.auth module."""

import pytest
import requests

from firebase_admin import dynamic_links

def test_get_stats():
    link_stats = dynamic_links.get_link_stats(
        'https://ds47s.app.goo.gl/uQWc',
        dynamic_links.StatOptions(duration_days=4000))
    assert isinstance(link_stats, dynamic_links.LinkStats)
    assert len(link_stats.event_stats)
    print link_stats.event_stats

def test_unautherized():
    with pytest.raises(requests.exceptions.HTTPError) as excinfo:
        dynamic_links.get_link_stats(
            'https://ds48s.app.goo.gl/uQWc',
            dynamic_links.StatOptions(duration_days=4000))
    assert excinfo.value.response.status_code == 403
        