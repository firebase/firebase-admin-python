"""Setup file for distribution artifacts."""
from __future__ import print_function

from os import path
import sys

from setuptools import find_packages
from setuptools import setup

import firebase_admin


if sys.version_info < (2, 7):
    print('firebase_admin requires python2 version >= 2.7.', file=sys.stderr)
    sys.exit(1)


long_description = ('The Firebase Admin Python SDK enables server-side (backend) Python developers '
                    'to integrate Firebase into their services and applications.')
install_requires = [
    'oauth2client>=4.0.0',
    'six>=1.6.1'
]

version = firebase_admin.__version__

setup(
    name='firebase_admin',
    version=version,
    description='Firebase Admin Python SDK',
    long_description=long_description,
    url='https://firebase.google.com/docs/admin/setup/',
    author='Firebase',
    license='https://firebase.google.com/terms/',
    keywords='firebase cloud development',
    install_requires=install_requires,
    packages=find_packages(exclude=['tests']),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.5',
    ],
)
