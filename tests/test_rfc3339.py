# Copyright 2020 Google Inc.
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

"""Test cases for the firebase_admin._rfc3339 module."""

import pytest

from firebase_admin import _rfc3339

def test_epoch():
    expected = pytest.approx(0)
    assert _rfc3339.parse_to_epoch("1970-01-01T00:00:00Z") == expected
    assert _rfc3339.parse_to_epoch("1970-01-01T00:00:00z") == expected
    assert _rfc3339.parse_to_epoch("1970-01-01T00:00:00+00:00") == expected
    assert _rfc3339.parse_to_epoch("1970-01-01T00:00:00-00:00") == expected
    assert _rfc3339.parse_to_epoch("1970-01-01T01:00:00+01:00") == expected
    assert _rfc3339.parse_to_epoch("1969-12-31T23:00:00-01:00") == expected

def test_pre_epoch():
    expected = -5617641600
    assert _rfc3339.parse_to_epoch("1791-12-26T00:00:00Z") == expected
    assert _rfc3339.parse_to_epoch("1791-12-26T00:00:00+00:00") == expected
    assert _rfc3339.parse_to_epoch("1791-12-26T00:00:00-00:00") == expected
    assert _rfc3339.parse_to_epoch("1791-12-26T01:00:00+01:00") == expected
    assert _rfc3339.parse_to_epoch("1791-12-25T23:00:00-01:00") == expected

def test_post_epoch():
    expected = 904892400
    assert _rfc3339.parse_to_epoch("1998-09-04T07:00:00Z") == expected
    assert _rfc3339.parse_to_epoch("1998-09-04T07:00:00+00:00") == expected
    assert _rfc3339.parse_to_epoch("1998-09-04T08:00:00+01:00") == expected
    assert _rfc3339.parse_to_epoch("1998-09-04T06:00:00-01:00") == expected

def test_micros_millis():
    assert _rfc3339.parse_to_epoch("1970-01-01T00:00:00Z") == pytest.approx(0)
    assert _rfc3339.parse_to_epoch("1970-01-01T00:00:00.1Z") == pytest.approx(0.1)
    assert _rfc3339.parse_to_epoch("1970-01-01T00:00:00.001Z") == pytest.approx(0.001)
    assert _rfc3339.parse_to_epoch("1970-01-01T00:00:00.000001Z") == pytest.approx(0.000001)

    assert _rfc3339.parse_to_epoch("1970-01-01T00:00:00+00:00") == pytest.approx(0)
    assert _rfc3339.parse_to_epoch("1970-01-01T00:00:00.1+00:00") == pytest.approx(0.1)
    assert _rfc3339.parse_to_epoch("1970-01-01T00:00:00.001+00:00") == pytest.approx(0.001)
    assert _rfc3339.parse_to_epoch("1970-01-01T00:00:00.000001+00:00") == pytest.approx(0.000001)

def test_nanos():
    assert _rfc3339.parse_to_epoch("1970-01-01T00:00:00.0000001Z") == pytest.approx(0)

@pytest.mark.parametrize('datestr', [
    'not a date string',
    '1970-01-01 00:00:00Z',
    '1970-01-01 00:00:00+00:00',
    '1970-01-01T00:00:00',
    ])
def test_bad_datestrs(datestr):
    with pytest.raises(ValueError):
        _rfc3339.parse_to_epoch(datestr)
