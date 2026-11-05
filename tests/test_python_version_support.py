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

"""Tests for firebase_admin._python_version_support."""

from collections import namedtuple
from unittest.mock import patch
import warnings

import pytest

from firebase_admin._python_version_support import check_python_version

_VersionInfo = namedtuple('_VersionInfo', ['major', 'minor'])


@pytest.mark.parametrize('version_tuple', [(3, 9), (3, 10)])
def test_deprecated_python_versions_emit_future_warning(version_tuple):
    mock_version = _VersionInfo(major=version_tuple[0], minor=version_tuple[1])
    version_str = f'{version_tuple[0]}.{version_tuple[1]}'

    with patch('firebase_admin._python_version_support.sys.version_info', mock_version):
        with pytest.warns(FutureWarning) as record:
            check_python_version()

    assert len(record) == 1
    assert record[0].filename == __file__
    expected = (
        f'Support for Python {version_str} in firebase-admin is deprecated '
        'and will be dropped in a future minor release. Please upgrade to '
        'Python 3.11 or higher to continue receiving updates.'
    )
    assert str(record[0].message) == expected


@pytest.mark.parametrize('version_tuple', [(3, 11), (3, 12), (3, 13), (3, 14), (3, 15)])
def test_supported_python_versions_do_not_warn(version_tuple):
    mock_version = _VersionInfo(major=version_tuple[0], minor=version_tuple[1])

    with patch('firebase_admin._python_version_support.sys.version_info', mock_version):
        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter('always')
            check_python_version()

    assert not recorded
