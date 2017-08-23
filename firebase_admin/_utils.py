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

"""Internal utilities common to all modules."""

import os

import firebase_admin

def _get_initialized_app(app):
    if app is None:
        return firebase_admin.get_app()
    elif isinstance(app, firebase_admin.App):
        initialized_app = firebase_admin.get_app(app.name)
        if app is not initialized_app:
            raise ValueError('Illegal app argument. App instance not '
                             'initialized via the firebase module.')
        return app
    else:
        raise ValueError('Illegal app argument. Argument must be of type '
                         ' firebase_admin.App, but given "{0}".'.format(type(app)))

def get_app_service(app, name, initializer):
    app = _get_initialized_app(app)
    return app._get_service(name, initializer) # pylint: disable=protected-access

def project_id(app):
    """Returns the project ID associated with the given App.

    This function first attempts to find the project ID from App options. If not present,
    it attempts to get the project ID from the authentication credential used to initialize
    the App. Finally, it attempts to get the project ID by referencing the GCLOUD_PROJECT
    environment variable.

    Args:
      app: A Firebase App instance.

    Returns:
      str: A project ID value or None.
    """
    pid = app.options.get('projectId')
    if not pid:
        credential = app.credential
        try:
            pid = credential.project_id
        except AttributeError:
            pass
    if not pid:
        pid = os.environ.get('GCLOUD_PROJECT')
    return pid
