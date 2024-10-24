# Copyright 2023 Google Inc.
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

"""Internal utilities for Firebase Realtime Database module"""

import time
import random
import math

_PUSH_CHARS = '-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz'

def time_now():
    return int(time.time()*1000)

def _generate_next_push_id():
    """Creates a unique push id generator.

    Creates 20-character string identifiers with the following properties:
        1. They're based on timestamps so that they sort after any existing ids.

        2. They contain 96-bits of random data after the timestamp so that IDs won't
        collide with other clients' IDs.

        3. They sort lexicographically*(so the timestamp is converted to characters
        that will sort properly).

        4. They're monotonically increasing. Even if you generate more than one in
        the same timestamp, the latter ones will sort after the former ones. We do
        this by using the previous random bits but "incrementing" them by 1 (only
        in the case of a timestamp collision).
    """

    # Timestamp of last push, used to prevent local collisions if you push twice
    # in one ms.
    last_push_time = 0

    # We generate 96-bits of randomness which get turned into 12 characters and
    # appended to the timestamp to prevent collisions with other clients. We
    # store the last characters we generated because in the event of a collision,
    # we'll use those same characters except "incremented" by one.
    last_rand_chars_indexes = []

    def next_push_id(now):
        nonlocal last_push_time
        nonlocal last_rand_chars_indexes
        is_duplicate_time = now == last_push_time
        last_push_time = now

        push_id = ''
        for _ in range(8):
            push_id = _PUSH_CHARS[now % 64] + push_id
            now = math.floor(now / 64)

        if not is_duplicate_time:
            last_rand_chars_indexes = []
            for _ in range(12):
                last_rand_chars_indexes.append(random.randrange(64))
        else:
            for index in range(11, -1, -1):
                if last_rand_chars_indexes[index] == 63:
                    last_rand_chars_indexes[index] = 0
                else:
                    break
            if index != 0:
                last_rand_chars_indexes[index] += 1
            elif index == 0 and last_rand_chars_indexes[index] != 0:
                last_rand_chars_indexes[index] += 1

        for index in range(12):
            push_id += _PUSH_CHARS[last_rand_chars_indexes[index]]

        if len(push_id) != 20:
            raise ValueError("push_id length should be 20")
        return push_id
    return next_push_id

get_next_push_id = _generate_next_push_id()
