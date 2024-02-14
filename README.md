[![Build Status](https://travis-ci.org/firebase/firebase-admin-python.svg?branch=master)](https://travis-ci.org/firebase/firebase-admin-python)
[![Python](https://img.shields.io/pypi/pyversions/firebase-admin.svg)](https://pypi.org/project/firebase-admin/)
[![Version](https://img.shields.io/pypi/v/firebase-admin.svg)](https://pypi.org/project/firebase-admin/)

# Firebase Admin Python SDK

## Table of Contents

 * [Overview](#overview)
 * [Installation](#installation)
 * [Contributing](#contributing)
 * [Supported Python Versions](#supported-python-versions)
 * [Documentation](#documentation)
 * [License and Terms](#license-and-terms)

## Overview

[Firebase](https://firebase.google.com) provides the tools and infrastructure
you need to develop apps, grow your user base, and earn money. The Firebase
Admin Python SDK enables access to Firebase services from privileged environments
(such as servers or cloud) in Python. Currently this SDK provides
Firebase custom authentication support.

Key Features of the Firebase Admin Python SDK:
* Authentication: Manage users, verify tokens, and integrate with Firebase Authentication.
* Realtime Database: Interact with Firebase Realtime Database, allowing you to retrieve, update, and listen for changes in the data stored in your Firebase database in real-time.
* Cloud Firestore: Access and manipulate documents and collections in Firestore, Firebase's NoSQL cloud database, with support for transactions, batched writes, and complex queries.
* Cloud Messaging (FCM): Send notifications or messages directly from your server to your users' devices via Firebase Cloud Messaging.
* Cloud Storage: Upload, download, and manage files stored in Firebase Cloud Storage.
* Remote Config: Programmatically change the behavior and appearance of your app without publishing an app update, by modifying configurations for different user segments.


For more information, visit the
[Firebase Admin SDK setup guide](https://firebase.google.com/docs/admin/setup/).

## Example Usage
Here's a simple example that demonstrates how to add a new document to a Firestore collection:
```
from firebase_admin import firestore

# Get a reference to the Firestore service
db = firestore.client()

# Add a new document
doc_ref = db.collection(u'users').document(u'alovelace')
doc_ref.set({
    u'first': u'Ada',
    u'last': u'Lovelace',
    u'born': 1815
})

print("Document added.")

```


## Installation

To install Firebase Admin Python SDK, simply execute the following command
in a terminal:

```
pip install firebase-admin
```
Before you can use the SDK, you need to initialize it with your project's credentials. This usually involves downloading a service account key from your Firebase project settings and initializing the SDK with this key.

Here's an example of how to initialize the Firebase Admin SDK in Python:
```
import firebase_admin
from firebase_admin import credentials

# Initialize the app with a service account, granting admin privileges
cred = credentials.Certificate('path/to/serviceAccountKey.json')
firebase_admin.initialize_app(cred)

```

## Contributing

Please refer to the [CONTRIBUTING page](./CONTRIBUTING.md) for more information
about how you can contribute to this project. We welcome bug reports, feature
requests, code review feedback, and also pull requests.


## Supported Python Versions

We currently support Python 3.7+. However, Python 3.7 support is deprecated,
and developers are strongly advised to use Python 3.8 or higher. Firebase
Admin Python SDK is also tested on PyPy and
[Google App Engine](https://cloud.google.com/appengine/) environments.


## Documentation

* [Setup Guide](https://firebase.google.com/docs/admin/setup/)
* [API Reference](https://firebase.google.com/docs/reference/admin/python/)


## License and Terms

Firebase Admin Python SDK is licensed under the
[Apache License, version 2.0](http://www.apache.org/licenses/LICENSE-2.0).

Your use of Firebase is governed by the
[Terms of Service for Firebase Services](https://firebase.google.com/terms/).
