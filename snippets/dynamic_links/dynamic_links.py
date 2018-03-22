# Copyright 2018 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from firebase_admin import dynamic_links


def get_link_stats():
    # [START get_link_stats]
    stat_options = dynamic_links.StatOptions(last_n_days=7)
    stats = dynamic_links.get_link_stats('https://abc.app.goo.gl/abc12', stat_options)
    # arrange the list results in a dict
    results = dict()
    for stat in stats.event_stats:
        results[(stat.platform, stat.event)] = stat.count
    andoid_click = results.get((dynamic_links.PLATFORM_ANDROID,
                                dynamic_links.EVENT_TYPE_CLICK))

    if andoid_click:
        print('There were {} clicks on ANDROID in the last 7 days'.format(andoid_click))
    # [END get_link_stats]
