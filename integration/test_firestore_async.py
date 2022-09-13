# Copyright 2022 Google Inc.
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

"""Integration tests for firebase_admin.firestore_async module."""
import datetime
import pytest

from firebase_admin import firestore_async

@pytest.mark.asyncio
async def test_firestore_async():
    client = firestore_async.client()
    expected = {
        'name': u'Mountain View',
        'country': u'USA',
        'population': 77846,
        'capital': False
    }
    doc = client.collection('cities').document()
    await doc.set(expected)

    data = await doc.get()
    assert data.to_dict() == expected

    await doc.delete()
    data = await doc.get()
    assert data.exists is False

@pytest.mark.asyncio
async def test_server_timestamp():
    client = firestore_async.client()
    expected = {
        'name': u'Mountain View',
        'timestamp': firestore_async.SERVER_TIMESTAMP # pylint: disable=no-member
    }
    doc = client.collection('cities').document()
    await doc.set(expected)

    data = await doc.get()
    data = data.to_dict()
    assert isinstance(data['timestamp'], datetime.datetime)
    await doc.delete()
