# Copyright 2018 Google Inc.
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

import firebase_admin
from firebase_admin import credentials
from firebase_admin import db

def authenticate_with_admin_privileges():
    # [START authenticate_with_admin_privileges]
    import firebase_admin
    from firebase_admin import credentials
    from firebase_admin import db

    # Fetch the service account key JSON file contents
    cred = credentials.Certificate('path/to/serviceAccountKey.json')

    # Initialize the app with a service account, granting admin privileges
    firebase_admin.initialize_app(cred, {
        'databaseURL': 'https://databaseName.firebaseio.com'
    })

    # As an admin, the app has access to read and write all data, regradless of Security Rules
    ref = db.reference('restricted_access/secret_document')
    print(ref.get())
    # [END authenticate_with_admin_privileges]
    firebase_admin.delete_app(firebase_admin.get_app())

def authenticate_with_limited_privileges():
    # [START authenticate_with_limited_privileges]
    import firebase_admin
    from firebase_admin import credentials
    from firebase_admin import db

    # Fetch the service account key JSON file contents
    cred = credentials.Certificate('path/to/serviceAccountKey.json')

    # Initialize the app with a custom auth variable, limiting the server's access
    firebase_admin.initialize_app(cred, {
        'databaseURL': 'https://databaseName.firebaseio.com',
        'databaseAuthVariableOverride': {
            'uid': 'my-service-worker'
        }
    })

    # The app only has access as defined in the Security Rules
    ref = db.reference('/some_resource')
    print(ref.get())
    # [END authenticate_with_limited_privileges]
    firebase_admin.delete_app(firebase_admin.get_app())

def authenticate_with_guest_privileges():
    # [START authenticate_with_guest_privileges]
    import firebase_admin
    from firebase_admin import credentials
    from firebase_admin import db

    # Fetch the service account key JSON file contents
    cred = credentials.Certificate('path/to/serviceAccountKey.json')

    # Initialize the app with a None auth variable, limiting the server's access
    firebase_admin.initialize_app(cred, {
        'databaseURL': 'https://databaseName.firebaseio.com',
        'databaseAuthVariableOverride': None
    })

    # The app only has access to public data as defined in the Security Rules
    ref = db.reference('/public_resource')
    print(ref.get())
    # [END authenticate_with_guest_privileges]
    firebase_admin.delete_app(firebase_admin.get_app())

def get_reference():
    # [START get_reference]
    # Import database module.
    from firebase_admin import db

    # Get a database reference to our blog.
    ref = db.reference('server/saving-data/fireblog')
    # [END get_reference]
    print(ref.key)

def set_value():
    ref = db.reference('server/saving-data/fireblog')

    # [START set_value]
    users_ref = ref.child('users')
    users_ref.set({
        'alanisawesome': {
            'date_of_birth': 'June 23, 1912',
            'full_name': 'Alan Turing'
        },
        'gracehop': {
            'date_of_birth': 'December 9, 1906',
            'full_name': 'Grace Hopper'
        }
    })
    # [END set_value]

def set_child_value():
    ref = db.reference('server/saving-data/fireblog')
    users_ref = ref.child('users')

    # [START set_child_value]
    users_ref.child('alanisawesome').set({
        'date_of_birth': 'June 23, 1912',
        'full_name': 'Alan Turing'
    })
    users_ref.child('gracehop').set({
        'date_of_birth': 'December 9, 1906',
        'full_name': 'Grace Hopper'
    })
    # [END set_child_value]

def update_child():
    ref = db.reference('server/saving-data/fireblog')
    users_ref = ref.child('users')

    # [START update_child]
    hopper_ref = users_ref.child('gracehop')
    hopper_ref.update({
        'nickname': 'Amazing Grace'
    })
    # [END update_child]

def update_children():
    ref = db.reference('server/saving-data/fireblog')
    users_ref = ref.child('users')

    # [START update_children]
    users_ref.update({
        'alanisawesome/nickname': 'Alan The Machine',
        'gracehop/nickname': 'Amazing Grace'
    })
    # [END update_children]

def overwrite_value():
    ref = db.reference('server/saving-data/fireblog')
    users_ref = ref.child('users')

    # [START overwrite_value]
    users_ref.update({
        'alanisawesome': {
            'nickname': 'Alan The Machine'
        },
        'gracehop': {
            'nickname': 'Amazing Grace'
        }
    })
    # [END overwrite_value]

def push_value():
    ref = db.reference('server/saving-data/fireblog')

    # [START push_value]
    posts_ref = ref.child('posts')

    new_post_ref = posts_ref.push()
    new_post_ref.set({
        'author': 'gracehop',
        'title': 'Announcing COBOL, a New Programming Language'
    })

    # We can also chain the two calls together
    posts_ref.push().set({
        'author': 'alanisawesome',
        'title': 'The Turing Machine'
    })
    # [END push_value]

def push_and_set_value():
    ref = db.reference('server/saving-data/fireblog')
    posts_ref = ref.child('posts')

    # [START push_and_set_value]
    # This is equivalent to the calls to push().set(...) above
    posts_ref.push({
        'author': 'gracehop',
        'title': 'Announcing COBOL, a New Programming Language'
    })
    # [END push_and_set_value]

def get_push_key():
    ref = db.reference('server/saving-data/fireblog')
    posts_ref = ref.child('posts')

    # [START push_key]
    # Generate a reference to a new location and add some data using push()
    new_post_ref = posts_ref.push()

    # Get the unique key generated by push()
    post_id = new_post_ref.key
    # [END push_key]
    print(post_id)

def run_transaction():
    # [START transaction]
    def increment_votes(current_value):
        return current_value + 1 if current_value else 1

    upvotes_ref = db.reference('server/saving-data/fireblog/posts/-JRHTHaIs-jNPLXOQivY/upvotes')
    try:
        new_vote_count = upvotes_ref.transaction(increment_votes)
        print('Transaction completed')
    except db.TransactionError:
        print('Transaction failed to commit')
    # [END transaction]

def read_value():
    # [START read_value]
    # Import database module.
    from firebase_admin import db

    # Get a database reference to our posts
    ref = db.reference('server/saving-data/fireblog/posts')

    # Read the data at the posts reference (this is a blocking operation)
    print(ref.get())
    # [END read_value]

def order_by_child():
    # [START order_by_child]
    ref = db.reference('dinosaurs')
    snapshot = ref.order_by_child('height').get()
    for key, val in snapshot.items():
        print('{0} was {1} meters tall'.format(key, val))
    # [END order_by_child]

def order_by_nested_child():
    # [START order_by_nested_child]
    ref = db.reference('dinosaurs')
    snapshot = ref.order_by_child('dimensions/height').get()
    for key, val in snapshot.items():
        print('{0} was {1} meters tall'.format(key, val))
    # [END order_by_nested_child]

def order_by_key():
    # [START order_by_key]
    ref = db.reference('dinosaurs')
    snapshot = ref.order_by_key().get()
    print(snapshot)
    # [END order_by_key]

def order_by_value():
    # [START order_by_value]
    ref = db.reference('scores')
    snapshot = ref.order_by_value().get()
    for key, val in snapshot.items():
        print('The {0} dinosaur\'s score is {1}'.format(key, val))
    # [END order_by_value]

def limit_query():
    # [START limit_query_1]
    ref = db.reference('dinosaurs')
    snapshot = ref.order_by_child('weight').limit_to_last(2).get()
    for key in snapshot:
        print(key)
    # [END limit_query_1]

    # [START limit_query_2]
    ref = db.reference('dinosaurs')
    snapshot = ref.order_by_child('height').limit_to_first(2).get()
    for key in snapshot:
        print(key)
    # [END limit_query_2]

    # [START limit_query_3]
    scores_ref = db.reference('scores')
    snapshot = scores_ref.order_by_value().limit_to_last(3).get()
    for key, val in snapshot.items():
        print('The {0} dinosaur\'s score is {1}'.format(key, val))
    # [END limit_query_3]

def range_query():
    # [START range_query_1]
    ref = db.reference('dinosaurs')
    snapshot = ref.order_by_child('height').start_at(3).get()
    for key in snapshot:
        print(key)
    # [END range_query_1]

    # [START range_query_2]
    ref = db.reference('dinosaurs')
    snapshot = ref.order_by_key().end_at('pterodactyl').get()
    for key in snapshot:
        print(key)
    # [END range_query_2]

    # [START range_query_3]
    ref = db.reference('dinosaurs')
    snapshot = ref.order_by_key().start_at('b').end_at(u'b\uf8ff').get()
    for key in snapshot:
        print(key)
    # [END range_query_3]

    # [START range_query_4]
    ref = db.reference('dinosaurs')
    snapshot = ref.order_by_child('height').equal_to(25).get()
    for key in snapshot:
        print(key)
    # [END range_query_4]

def complex_query():
    # [START complex_query]
    ref = db.reference('dinosaurs')
    favotire_dino_height = ref.child('stegosaurus').child('height').get()
    query = ref.order_by_child('height').end_at(favotire_dino_height).limit_to_last(2)
    snapshot = query.get()
    if len(snapshot) == 2:
        # Data is ordered by increasing height, so we want the first entry.
        # Second entry is stegosarus.
        for key in snapshot:
            print('The dinosaur just shorter than the stegosaurus is {0}'.format(key))
            return
    else:
        print('The stegosaurus is the shortest dino')
    # [END complex_query]


service_account = 'path/to/serviceAccount.json'
database_url = 'https://databaseName.firebaseio.com'

cred = credentials.Certificate(service_account)
firebase_admin.initialize_app(cred, {
    'databaseURL': database_url
})

get_reference()
set_value()
set_child_value()
update_child()
update_children()
overwrite_value()
push_value()
push_and_set_value()
get_push_key()
run_transaction()

read_value()
order_by_child()
#order_by_nested_child()
order_by_key()
order_by_value()
limit_query()
range_query()
complex_query()

firebase_admin.delete_app(firebase_admin.get_app())
