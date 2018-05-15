# Copyright 2017 Google Inc. All Rights Reserved.
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

from __future__ import print_function

# [START get_service_account_tokens]
from firebase_admin import credentials

cred = credentials.Certificate('path/to/serviceAccountKey.json')
access_token_info = cred.get_access_token()

access_token = access_token_info.access_token
expiration_time = access_token_info.expiry
# Attach access_token to HTTPS request in the "Authorization: Bearer" header
# After expiration_time, you must generate a new access token
# [END get_service_account_tokens]

print('The access token {} expires at {}'.format(access_token, expiration_time))
