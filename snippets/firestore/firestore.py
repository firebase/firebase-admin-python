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

from firebase_admin import firestore

# pylint: disable=invalid-name
def init_firestore_client():
    # [START init_firestore_client]
    import firebase_admin
    from firebase_admin import firestore

    # Application Default credentials are automatically created.
    app = firebase_admin.initialize_app()
    db = firestore.client()
    # [END init_firestore_client]

def init_firestore_client_application_default():
    # [START init_firestore_client_application_default]
    import firebase_admin
    from firebase_admin import credentials
    from firebase_admin import firestore

    # Use the application default credentials.
    cred = credentials.ApplicationDefault()

    firebase_admin.initialize_app(cred)
    db = firestore.client()
    # [END init_firestore_client_application_default]

def init_firestore_client_service_account():
    # [START init_firestore_client_service_account]
    import firebase_admin
    from firebase_admin import credentials
    from firebase_admin import firestore

    # Use a service account.
    cred = credentials.Certificate('path/to/serviceAccount.json')

    app = firebase_admin.initialize_app(cred)

    db = firestore.client()
    # [END init_firestore_client_service_account]

def read_data():
    import firebase_admin
    from firebase_admin import firestore

    app = firebase_admin.initialize_app()
    db = firestore.client()

    # [START read_data]
    doc_ref = db.collection('users').document('alovelace')
    doc = doc_ref.get()
    if doc.exists:
        return f'data: {doc.to_dict()}'
    return "Document does not exist."
    # [END read_data]

def add_data():
    import firebase_admin
    from firebase_admin import firestore

    app = firebase_admin.initialize_app()
    db = firestore.client()

    # [START add_data]
    doc_ref = db.collection("users").document("alovelace")
    doc_ref.set({
        "first": "Ada",
        "last": "Lovelace",
        "born": 1815
    })
    # [END add_data]
