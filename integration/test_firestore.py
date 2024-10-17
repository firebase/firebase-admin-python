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

"""Integration tests for firebase_admin.firestore module."""
import datetime

from firebase_admin import firestore

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


def test_firestore():
    client = firestore.client()
    expected = {
        'name': u'Mountain View',
        'country': u'USA',
        'population': 77846,
        'capital': False
    }
    doc = client.collection('cities').document()
    doc.set(expected)

    data = doc.get().to_dict()
    assert data == expected

    doc.delete()
    assert doc.get().exists is False

def test_firestore_explicit_database_id():
    client = firestore.client(database_id='testing-database')
    expected = _CITY
    doc = client.collection('cities').document()
    doc.set(expected)

    data = doc.get()
    assert data.to_dict() == expected

    doc.delete()
    data = doc.get()
    assert data.exists is False

def test_firestore_multi_db():
    city_client = firestore.client()
    movie_client = firestore.client(database_id='testing-database')

    expected_city = _CITY
    expected_movie = _MOVIE

    city_doc = city_client.collection('cities').document()
    movie_doc = movie_client.collection('movies').document()

    city_doc.set(expected_city)
    movie_doc.set(expected_movie)

    city_data = city_doc.get()
    movie_data = movie_doc.get()

    assert city_data.to_dict() == expected_city
    assert movie_data.to_dict() == expected_movie

    city_doc.delete()
    movie_doc.delete()

    city_data = city_doc.get()
    movie_data = movie_doc.get()

    assert city_data.exists is False
    assert movie_data.exists is False

def test_server_timestamp():
    client = firestore.client()
    expected = {
        'name': u'Mountain View',
        'timestamp': firestore.SERVER_TIMESTAMP # pylint: disable=no-member
    }
    doc = client.collection('cities').document()
    doc.set(expected)

    data = doc.get().to_dict()
    assert isinstance(data['timestamp'], datetime.datetime)
    doc.delete()
