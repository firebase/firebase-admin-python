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

"""Firebase Dynamic Links module.

This module lets admins get statistics for a Firebase dynamic link.
"""

import requests
from six.moves import urllib
import six

from firebase_admin import _http_client
from firebase_admin import _utils



PLATFORM_DESKTOP = 'desktop'
PLATFORM_IOS = 'ios'
PLATFORM_ANDROID = 'android'

EVENT_TYPE_CLICK = 'click'
EVENT_TYPE_REDIRECT = 'redirect'
EVENT_TYPE_APP_INSTALL = 'app_install'
EVENT_TYPE_APP_FIRST_OPEN = 'app_first_open'
EVENT_TYPE_APP_RE_OPEN = 'app_re_open'

_platforms = {
    'DESKTOP': PLATFORM_DESKTOP,
    'IOS': PLATFORM_IOS,
    'ANDROID': PLATFORM_ANDROID
}

_event_types = {
    'CLICK': EVENT_TYPE_CLICK,
    'REDIRECT': EVENT_TYPE_REDIRECT,
    'APP_INSTALL': EVENT_TYPE_APP_INSTALL,
    'APP_FIRST_OPEN': EVENT_TYPE_APP_FIRST_OPEN,
    'APP_RE_OPEN': EVENT_TYPE_APP_RE_OPEN
}

_LINKS_ATTRIBUTE = '_dynamic_links'
_LINKS_BASE_URL = 'https://firebasedynamiclinks.googleapis.com/v1/'

_UNKNOWN_ERROR = 'unknown-error'
def get_link_stats(short_link, stat_options, app=None):
    """ Returns a ``LinkStats`` object with the event statistics for the given short link

    Args:
        short_link: The string of the designated short link. e.g. https://abc12.app.goo.gl/link
                    The link must belong to the project associated with the service account
                    used to call this API.
        stat_options: An object containing a single field "duration_days" for which the statistics
                      are retrieved.
        app: A Firebase ``App instance`` (optional). (If missing uses default app.)

    Returns:
        LinkStats: A ``LinkStats`` object. (containing an array of ``EventStats``)

    Raises:
        ValueError: If any of the arguments are invalid.
            short_link must start with the "https" protocol.
            stat_options should have duration_days > 0.
    """
    return _get_link_service(app).get_stats(short_link, stat_options)

def _get_link_service(app):
    """Returns an _DynamicLinksService instance for an App.

    If the App already has a _DynamicLinksService associated with it, simply returns
    it. Otherwise creates a new _DynamicLinksService, and adds it to the App before
    returning it.

    Args:
        app: A Firebase App instance (or None to use the default App).

    Returns:
        _DynamicLinksService: An `_DynamicLinksService` for the specified App instance.

    Raises:
        ValueError: If the app argument is invalid.
    """
    return _utils.get_app_service(app, _LINKS_ATTRIBUTE, _DynamicLinksService)


class LinkStats(object):
    """The ``LinkStats`` object is returned by get_link_stats, it contains a list of
       ``EventStats``"""
    def __init__(self, event_stats):
        if not isinstance(event_stats, (list, tuple)):
            raise ValueError('Invalid data argument: {0}. Must be a list or tuple'
                             .format(event_stats))
        if not all(isinstance(es, EventStats) for es in event_stats):
            raise ValueError('Invalid data argument: elements of event stats must be' +
                             ' "EventStats", found{}'.format(type(event_stats[0])))
        self._stats = event_stats

    @property
    def event_stats(self):
        """Returns the event statistics for this link, for the requested period.

        Returns:
          event_stats: A list of ``EventStats``.
        """
        return self._stats

class EventStats(object):
    """``EventStat`` is a single stat item containing (platform, event, count)"""

    def __init__(self, **kwargs):
        """Create new instance of EventStats(platform, event, count)
           The input values are the strings returned by the REST call.
           The internal values stored in the ``EventStats`` object are
           the package constants named at the start of this package."""
        required = {'platform', 'event', 'count'}
        params = set(kwargs.keys())
        missing = required - params
        unexpected = params - required
        if missing:
            raise ValueError('Missing arguments for EventStats: {}'.format(missing))
        if unexpected:
            raise ValueError('Unexpected arguments for EventStats: {}'.format(unexpected))

        platform = kwargs['platform']
        if not isinstance(platform, six.string_types) or platform not in _platforms.keys():
            raise ValueError('Invalid Platform value "{}".'.format(platform))
        self._platform = _platforms[platform]

        event = kwargs['event']
        if not isinstance(event, six.string_types) or event not in _event_types.keys():
            raise ValueError('Invalid Event Type value "{}".'.format(event))
        self._event = _event_types[event]

        count = kwargs['count']
        if(not ((isinstance(count, six.string_types)    # a string
                 and count.isdigit())                   # ... that is made of digits(non negative)
                or (not isinstance(count, bool)         # bool is confused as an instance of int
                    and isinstance(count, (int, float)) # number
                    and count >= 0))):                  # non negative
            raise ValueError('Invalid Count, must be a non negative int, "{}".'.format(count))
        self._count = int(count)

    @property
    def platform(self):
        return self._platform

    @property
    def event(self):
        return self._event

    @property
    def count(self):
        return self._count


class StatOptions(object):
    def __init__(self, duration_days):
        if (isinstance(duration_days, bool)
                or not isinstance(duration_days, int)
                or duration_days < 1):
            raise ValueError('duration_days must be positive integer (got {})'
                             .format(duration_days))
        self._duration_days = duration_days

    @property
    def duration_days(self):
        return self._duration_days


class _DynamicLinksService(object):
    """Provides methods for the Firebase dynamic links interaction"""

    INTERNAL_ERROR = 'internal-error'

    def __init__(self, app):
        self._client = _http_client.JsonHttpClient(
            credential=app.credential.get_credential(),
            base_url=_LINKS_BASE_URL)
        self._timeout = app.options.get('httpTimeout')
        self._request_string = '{0}/linkStats?durationDays={1}'

    def _format_request_string(self, short_link, options):
        days = options.duration_days
        # Complaints about the named second argument needed to replace "/"
        url_quoted = urllib.parse.quote(short_link, safe='') #pylint: disable=redundant-keyword-arg
        return self._request_string.format(url_quoted, days)

    def get_stats(self, short_link, stat_options):
        """Returns the LinkStats of the requested short_link for the duration set in options"""
        if(not isinstance(short_link, six.string_types)
           or not short_link.startswith('https://')):
            raise ValueError('short_link must be a string and begin with "https://".')
        if not isinstance(stat_options, StatOptions):
            raise ValueError('stat_options must be of type StatOptions.')

        request_string = self._format_request_string(short_link, stat_options)
        try:
            resp = self._client.body('get', request_string, timeout=self._timeout)
        except requests.exceptions.RequestException as error:
            self._handle_error(error)
        else:
            link_event_stats = resp.get('linkEventStats', [])
            event_stats = [EventStats(**es) for es in link_event_stats]
            return LinkStats(event_stats)

    def _handle_error(self, error):
        """Error handler for dynamic links request errors"""
        if error.response is None:
            msg = 'Failed to call dynamic links API: {0}'.format(error)
            raise ApiCallError(self.INTERNAL_ERROR, msg, error)
        data = {}
        try:
            parsed_body = error.response.json()
            if isinstance(parsed_body, dict):
                data = parsed_body
        except ValueError:
            pass
        error_details = data.get('error', {})
        code = error_details.get('code', _UNKNOWN_ERROR)
        msg = error_details.get('message')
        if not msg:
            msg = 'Unexpected HTTP response with status: {0}; body: {1}'.format(
                error.response.status_code, error.response.content.decode())
        raise ApiCallError(code, msg, error)


class ApiCallError(Exception):
    """Represents an Exception encountered while invoking the Firebase dynamic links API."""

    def __init__(self, code, message, error=None):
        Exception.__init__(self, message)
        self.code = code
        self.detail = error
