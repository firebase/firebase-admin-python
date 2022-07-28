# Copyright 2022 Google Inc.
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

import asyncio

from firebase_admin import firestore_async

# pylint: disable=invalid-name
def init_firestore_async_client():
    # [START init_firestore_async_client]
    import firebase_admin
    from firebase_admin import firestore_async

    # Application Default credentials are automatically created.
    app = firebase_admin.initialize_app()
    db = firestore_async.client()
    # [END init_firestore_async_client]

def init_firestore_async_client_application_default():
    # [START init_firestore_async_client_application_default]
    import firebase_admin
    from firebase_admin import credentials
    from firebase_admin import firestore_async

    # Use the application default credentials.
    cred = credentials.ApplicationDefault()

    firebase_admin.initialize_app(cred)
    db = firestore_async.client()
    # [END init_firestore_async_client_application_default]

def init_firestore_async_client_service_account():
    # [START init_firestore_async_client_service_account]
    import firebase_admin
    from firebase_admin import credentials
    from firebase_admin import firestore_async

    # Use a service account.
    cred = credentials.Certificate('path/to/serviceAccount.json')

    app = firebase_admin.initialize_app(cred)

    db = firestore_async.client()
    # [END init_firestore_async_client_service_account]

def close_async_sessions():
    import firebase_admin
    from firebase_admin import firestore_async

    # [START close_async_sessions]
    app = firebase_admin.initialize_app()
    db = firestore_async.client()

    # Perform firestore tasks...

    # Delete app to ensure that all the async sessions are closed gracefully.
    firebase_admin.delete_app(app)
    # [END close_async_sessions]

async def read_data():
    import firebase_admin
    from firebase_admin import firestore_async

    app = firebase_admin.initialize_app()
    db = firestore_async.client()

    # [START read_data]
    doc_ref = db.collection('users').document('alovelace')
    doc = await doc_ref.get()
    if doc.exists:
        return f'data: {doc.to_dict()}'
    # [END read_data]

async def add_data():
    import firebase_admin
    from firebase_admin import firestore_async

    app = firebase_admin.initialize_app()
    db = firestore_async.client()

    # [START add_data]
    doc_ref = db.collection("users").document("alovelace")
    await doc_ref.set({
        "first": "Ada",
        "last": "Lovelace",
        "born": 1815
    })
    # [END add_data]

def firestore_async_client_with_asyncio_eventloop():
    # [START firestore_async_client_with_asyncio_eventloop]
    import asyncio
    import firebase_admin
    from firebase_admin import firestore_async

    app = firebase_admin.initialize_app()
    db = firestore_async.client()

    # Create coroutine to add user data.
    async def add_data():
        doc_ref = db.collection("users").document("alovelace")
        print("Start adding user...")
        await doc_ref.set({
            "first": "Ada",
            "last": "Lovelace",
            "born": 1815
        })
        print("Done adding user!")

    # Another corutine with secondary tasks we want to complete.
    async def while_waiting():
        print("Start other tasks...")
        await asyncio.sleep(2)
        print("Finished with other tasks!")

    # Initialize an eventloop to execute tasks until completion.
    loop = asyncio.get_event_loop()
    tasks = [add_data(), while_waiting()]
    loop.run_until_complete(asyncio.gather(*tasks))
    firebase_admin.delete_app(app)
    # [END firestore_async_client_with_asyncio_eventloop]
