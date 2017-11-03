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

"""Setup file for distribution artifacts."""
from __future__ import print_function

from os import path
import sys

from setuptools import find_packages
from setuptools import setup

import firebase_admin


if sys.version_info < (2, 7):
    print('firebase_admin requires python2 version >= 2.7 or python3.', file=sys.stderr)
    sys.exit(1)


long_description = ('The Firebase Admin Python SDK enables server-side (backend) Python developers '
                    'to integrate Firebase into their services and applications.')
install_requires = [
    'google-auth>=1.1.0',
    'google-cloud-firestore>=0.27.0',
    'google-cloud-storage>=1.2.0',    
    'requests>=2.13.0',
    'six>=1.6.1'
]

extras_require = {
    ':python_version<"3.4"': ('enum34>=1.0.4',),
}

version = firebase_admin.__version__

setup(
    name='firebase_admin',
    version=version,
    description='Firebase Admin Python SDK',
    long_description=long_description,
    url='https://firebase.google.com/docs/admin/setup/',
    author='Firebase',
    license='Apache License 2.0',
    keywords='firebase cloud development',
    extras_require=extras_require,
    install_requires=install_requires,
    packages=find_packages(exclude=['tests']),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.5',
        'License :: OSI Approved :: Apache Software License',
    ],
)
