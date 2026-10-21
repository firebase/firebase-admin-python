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

"""Code to check Python versions supported by the Firebase Admin Python SDK.

Adapted from ``google.api_core._python_version_support``.
"""

import datetime
import enum
import sys
import textwrap
from typing import Dict, List, NamedTuple, Optional, Tuple
import warnings


class PythonVersionStatus(enum.Enum):
    """Support status of a Python version in this SDK release."""

    PYTHON_VERSION_SUPPORTED = 'PYTHON_VERSION_SUPPORTED'
    """This Python version is fully supported, so the SDK running on this
    version will have all features and bug fixes."""

    PYTHON_VERSION_DEPRECATED = 'PYTHON_VERSION_DEPRECATED'
    """This Python version is still supported, but support will end within a
    year. At that time, there will be no more releases for this SDK
    running under this Python version."""

    PYTHON_VERSION_EOL = 'PYTHON_VERSION_EOL'
    """This Python version has reached its end of life in the Python community
    (see https://devguide.python.org/versions/), and this SDK will cease
    supporting this Python version within the next few releases."""

    PYTHON_VERSION_UNSUPPORTED = 'PYTHON_VERSION_UNSUPPORTED'
    """This release of the SDK may not be the latest, since current releases no
    longer support this Python version."""


class VersionInfo(NamedTuple):
    """Hold release and support date information for a Python version."""

    version: str
    python_start: datetime.date
    python_eol: datetime.date
    deprecation_date: Optional[datetime.date] = None
    end_of_support_date: Optional[datetime.date] = None


PYTHON_VERSIONS: List[VersionInfo] = [
    # Refer to https://devguide.python.org/versions/ and the PEPs linked therefrom.
    VersionInfo(
        version='3.9',
        python_start=datetime.date(2020, 10, 5),
        python_eol=datetime.date(2025, 10, 5),
    ),
    VersionInfo(
        version='3.10',
        python_start=datetime.date(2021, 10, 4),
        python_eol=datetime.date(2026, 10, 4),
    ),
    VersionInfo(
        version='3.11',
        python_start=datetime.date(2022, 10, 24),
        python_eol=datetime.date(2027, 10, 24),
    ),
    VersionInfo(
        version='3.12',
        python_start=datetime.date(2023, 10, 2),
        python_eol=datetime.date(2028, 10, 2),
    ),
    VersionInfo(
        version='3.13',
        python_start=datetime.date(2024, 10, 7),
        python_eol=datetime.date(2029, 10, 7),
    ),
    VersionInfo(
        version='3.14',
        python_start=datetime.date(2025, 10, 7),
        python_eol=datetime.date(2030, 10, 7),
    ),
]

PYTHON_VERSION_INFO: Dict[Tuple[int, int], VersionInfo] = {
    (int(info.version.split('.')[0]), int(info.version.split('.')[1])): info
    for info in PYTHON_VERSIONS
}

LOWEST_TRACKED_VERSION = min(PYTHON_VERSION_INFO.keys())
_FAKE_PAST_DATE = datetime.date.min + datetime.timedelta(days=900)
_FAKE_PAST_VERSION = VersionInfo(
    version='0.0',
    python_start=_FAKE_PAST_DATE,
    python_eol=_FAKE_PAST_DATE,
)
_FAKE_FUTURE_DATE = datetime.date.max - datetime.timedelta(days=900)
_FAKE_FUTURE_VERSION = VersionInfo(
    version='999.0',
    python_start=_FAKE_FUTURE_DATE,
    python_eol=_FAKE_FUTURE_DATE,
)
DEPRECATION_WARNING_PERIOD = datetime.timedelta(days=365)
EOL_GRACE_PERIOD = datetime.timedelta(weeks=1)
_PACKAGE_LABEL = 'package firebase-admin (firebase_admin)'


def _flatten_message(text: str) -> str:
    """Dedent a multi-line string and flatten it into a single line."""
    return ' '.join(textwrap.dedent(text).strip().split())


def check_python_version(
        today: Optional[datetime.date] = None) -> PythonVersionStatus:
    """Check the running Python version and issue a support warning if needed.

    Args:
        today: The date to check against. Defaults to the current date.

    Returns:
        PythonVersionStatus: The support status of the current Python version.
    """
    today = today or datetime.date.today()

    python_version = sys.version_info
    version_tuple = (python_version.major, python_version.minor)
    py_version_str = sys.version.split()[0]

    version_info = PYTHON_VERSION_INFO.get(version_tuple)

    if not version_info:
        if version_tuple < LOWEST_TRACKED_VERSION:
            version_info = _FAKE_PAST_VERSION
        else:
            version_info = _FAKE_FUTURE_VERSION

    deprecation_date = version_info.deprecation_date or (
        version_info.python_eol - DEPRECATION_WARNING_PERIOD
    )
    end_of_support_date = version_info.end_of_support_date or (
        version_info.python_eol + EOL_GRACE_PERIOD
    )

    def min_python(date: datetime.date) -> str:
        """Find the minimum supported Python version for a given date."""
        for version, info in sorted(PYTHON_VERSION_INFO.items()):
            if info.python_start <= date < info.python_eol:
                return f'Python {version[0]}.{version[1]}'
        return 'a currently supported Python version [https://devguide.python.org/versions]'

    if end_of_support_date < today:
        message = _flatten_message(
            f"""
            You are using a non-supported Python version ({py_version_str}).
            Google will not post any further updates to {_PACKAGE_LABEL}
            supporting this Python version. Please upgrade to the latest Python
            version, or at least {min_python(today)}, and then update
            {_PACKAGE_LABEL}.
            """
        )
        warnings.warn(message, FutureWarning, stacklevel=2)
        return PythonVersionStatus.PYTHON_VERSION_UNSUPPORTED

    if version_info.python_eol <= today <= end_of_support_date:
        message = _flatten_message(
            f"""
            You are using a Python version ({py_version_str})
            past its end of life. Google will update {_PACKAGE_LABEL}
            with critical bug fixes on a best-effort basis, but not
            with any other fixes or features. Please upgrade
            to the latest Python version, or at least
            {min_python(today)}, and then update {_PACKAGE_LABEL}.
            """
        )
        warnings.warn(message, FutureWarning, stacklevel=2)
        return PythonVersionStatus.PYTHON_VERSION_EOL

    if deprecation_date <= today < version_info.python_eol:
        message = _flatten_message(
            f"""
            You are using a Python version ({py_version_str}) which Google will
            stop supporting in new releases of {_PACKAGE_LABEL} once it reaches
            its end of life ({version_info.python_eol}). Please upgrade to the
            latest Python version, or at least
            {min_python(version_info.python_eol)}, to continue receiving updates
            for {_PACKAGE_LABEL} past that date.
            """
        )
        warnings.warn(message, FutureWarning, stacklevel=2)
        return PythonVersionStatus.PYTHON_VERSION_DEPRECATED

    return PythonVersionStatus.PYTHON_VERSION_SUPPORTED
