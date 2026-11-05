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

"""Runtime Python version deprecation check for the Firebase Admin SDK."""

import sys
import warnings

# Minimum Python (major, minor) version that does not emit a deprecation warning.
# Bump this tuple in a minor release to deprecate an older Python version ahead
# of dropping it in a future release.
_MIN_NON_DEPRECATED_VERSION = (3, 11)


def check_python_version() -> None:
    """Emits a FutureWarning if the running Python version is deprecated."""
    current = (sys.version_info.major, sys.version_info.minor)
    if current < _MIN_NON_DEPRECATED_VERSION:
        current_str = f'{current[0]}.{current[1]}'
        recommended_str = (
            f'{_MIN_NON_DEPRECATED_VERSION[0]}.{_MIN_NON_DEPRECATED_VERSION[1]}'
        )
        warnings.warn(
            f'Support for Python {current_str} in firebase-admin is deprecated '
            'and will be dropped in a future minor release. Please upgrade to '
            f'Python {recommended_str} or higher to continue receiving updates.',
            FutureWarning,
            stacklevel=2,
        )
