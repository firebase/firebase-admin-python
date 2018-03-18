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

This module lets admins get the stats for a dynamic link.
"""

from collections import namedtuple

from six.moves import urllib_parse

from firebase_admin import _http_client
from firebase_admin import _utils


_LINKS_ATTRIBUTE = '_links'
_LINKS_BASE_URL = 'https://firebasedynamiclinks.googleapis.com/v1/'

PLATFORM_DESKTOP = 'desktop'
PLATFORM_IOS = 'ios'
PLATFORM_ANDROID = 'android'

EVENT_TYPE_CLICK = 'click'
EVENT_TYPE_REDIRECT = 'redirect'
EVENT_TYPE_APP_INSTALL = 'app_install'
EVENT_TYPE_APP_FIRST_OPEN = 'app_first_open'
EVENT_TYPE_APP_RE_OPEN = 'app_re_open'

StatOptions = namedtuple('StatOptions', ['duration_days'])

def get_link_stats(short_link, stat_options, app=None):
    """ Returns a LinkStats object with the event stats for the given short link

    Args:
      short_link: The string of the designated short link. e.g. https://abc12.app.goo.gl/link
                  The link must belong to the project associated with the service account
                  used to call this API.
      stat_options: an object containing a single field "duration_days" for which the
      app: a firebase_app instance or None, for default.

    Returns:
      LinkStats: an LinkStats object. (containing an array of EventStats)
    """
    return _get_link_service(app).get_stats(short_link, stat_options)

def _get_link_service(app):
    """Returns an _LinksService instance for an App.

    If the App already has an _LinksService associated with it, simply returns
    it. Otherwise creates a new _LinksService, and adds it to the App before
    returning it.

    Args:
      app: A Firebase App instance (or None to use the default App).

    Returns:
      _LinksService: An _LinksService for the specified App instance.

    Raises:
      ValueError: If the app argument is invalid.
    """
    return _utils.get_app_service(app, _LINKS_ATTRIBUTE, _LinksService)


class LinkStats(object):
    def __init__(self, event_stats):
        if not isinstance(event_stats, list):
            raise ValueError('Invalid data argument: {0}. Must be a list.'.format(event_stats))
        if len(event_stats) > 0 and not isinstance(event_stats[0], EventStats):
            raise ValueError('Invalid data argument: elements of event stats must be' +
                             ' "EventStats", found{}'.format(type(event_stats[0])))
        self._stats = event_stats

    @property
    def event_stats(self):
        """Returns the event_stats for this link.

        Returns:
          event_stats: A list of EventStats.
        """
        return self._stats


class _LinksService(object):
    """Provides methods for the Firebase Dynamic Links interaction"""
    def __init__(self, app):
        self._client = _http_client.JsonHttpClient(
            credential=app.credential.get_credential(),
            base_url=_LINKS_BASE_URL)
        self._timeout = app.options.get('httpTimeout')
        self._links_request = '{0}/linkStats?durationDays={1}'

    def _populated_request(self, url, options):
        days = options.duration_days
        url_quoted = urllib_parse.quote(url, safe="")
        return self._links_request.format(url_quoted, days)

    def get_stats(self, url, options):
        url_p = self._populated_request(url, options)
        resp = self._client.request('get', url_p)
        link_event_stats = resp.json().get('linkEventStats', [])
        #        print link_event_stats, ":::::::::::::::"
        event_stats = [EventStats.from_json(**es) for es in link_event_stats]

        return LinkStats(event_stats)

class EventStats(object):
    """EventStats is a single stat item containing (platform, event, count)"""
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

    def __init__(self, platform, event, count):
        """Create new instance of EventStats(platform, event, count)"""
        self.platform = platform
        self.event = event
        self.count = count

    @classmethod
    def from_json(cls, platform, event, count):
        return EventStats(cls._platforms[platform],
                          cls._event_types[event],
                          count)

    @property
    def platform(self):
        return self._platform

    @platform.setter
    def platform(self, platform):
        if platform not in self._platforms.values():
            print platform, self._platforms.values(), "::::::'';';';';'"
            raise ValueError('platform {}, not recognized'.format(platform))
        self._platform = platform

    @property
    def event(self):
        return self._event

    @event.setter
    def event(self, event):
        if event not in self._event_types.values():
            raise ValueError('event_type {}, not recognized'.format(event))
        self._event = event

    @property
    def count(self):
        return self._count

    @count.setter
    def count(self, count):
        if not isinstance(count, int):
            raise ValueError('Count must be int', count)
        self._count = count
        