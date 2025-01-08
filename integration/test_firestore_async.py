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
import asyncio
import datetime
import pytest

from firebase_admin import firestore_async

_CITY = {
        'name': u'Mountain View',
        'country': u'USA',
        'population': 77846,
        'capital': False
    }

_MOVIE = {
        'Name': u'Interstellar',
        'Year': 2014,
        'Runtime': u'2h 49m',
        'Academy Award Winner': True
    }


@pytest.mark.asyncio
async def test_firestore_async():
    client = firestore_async.client()
    expected = _CITY
    doc = client.collection('cities').document()
    await doc.set(expected)

    data = await doc.get()
    assert data.to_dict() == expected

    await doc.delete()
    data = await doc.get()
    assert data.exists is False

@pytest.mark.asyncio
async def test_firestore_async_explicit_database_id():
    client = firestore_async.client(database_id='testing-database')
    expected = _CITY
    doc = client.collection('cities').document()
    await doc.set(expected)

    data = await doc.get()
    assert data.to_dict() == expected

    await doc.delete()
    data = await doc.get()
    assert data.exists is False

@pytest.mark.asyncio
async def test_firestore_async_multi_db():
    city_client = firestore_async.client()
    movie_client = firestore_async.client(database_id='testing-database')

    expected_city = _CITY
    expected_movie = _MOVIE

    city_doc = city_client.collection('cities').document()
    movie_doc = movie_client.collection('movies').document()

    await asyncio.gather(
        city_doc.set(expected_city),
        movie_doc.set(expected_movie)
    )

    data = await asyncio.gather(
        city_doc.get(),
        movie_doc.get()
    )

    assert data[0].to_dict() == expected_city
    assert data[1].to_dict() == expected_movie

    await asyncio.gather(
        city_doc.delete(),
        movie_doc.delete()
    )

    data = await asyncio.gather(
        city_doc.get(),
        movie_doc.get()
    )
    assert data[0].exists is False
    assert data[1].exists is False

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
