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

"""Test cases for the firebase_admin.app_check module."""

import pytest

import firebase_admin
from firebase_admin import app_check
from tests import testutils
import jwt
from jwt import PyJWK

NON_STRING_ARGS = [list(), tuple(), dict(), True, False, 1, 0]

class TestBatch:

    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': 'explicit-project-id'})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

class TestVerifyToken(TestBatch):

    def test_no_project_id(self):
        def evaluate():
            app = firebase_admin.initialize_app(testutils.MockCredential(), name='no_project_id')
            with pytest.raises(ValueError):
                app_check.verify_token(token="app_check_token", app=app)
        testutils.run_without_project_id(evaluate)

    @pytest.mark.parametrize('token', NON_STRING_ARGS)
    def test_verify_token_with_non_string_raises_error(self, token):
        with pytest.raises(ValueError) as excinfo:
            app_check.verify_token(token)
        expected = 'app check token "{0}" must be a string.'.format(token)
        assert str(excinfo.value) == expected

    def test_has_valid_token_headers(self):
        app = firebase_admin.get_app()
        app_check_service = app_check._get_app_check_service(app)

        headers = {"alg": "RS256", 'typ': "JWT"} 
        assert None == app_check_service._has_valid_token_headers(headers=headers)
    
    def test_has_valid_token_headers_with_incorrect_type_raises_error(self):
        app = firebase_admin.get_app()
        app_check_service = app_check._get_app_check_service(app)
        headers = {"alg": "RS256", 'typ': "WRONG"}
        with pytest.raises(ValueError) as excinfo:
            app_check_service._has_valid_token_headers(headers=headers)

        expected = 'The provided App Check token has an incorrect type header'
        assert str(excinfo.value) == expected
    
    def test_has_valid_token_headers_with_incorrect_algorithm_raises_error(self):
        app = firebase_admin.get_app()
        app_check_service = app_check._get_app_check_service(app)
        headers = {"alg": "HS256", 'typ': "JWT"}
        with pytest.raises(ValueError) as excinfo:
            app_check_service._has_valid_token_headers(headers=headers)

        expected = 'The provided App Check token has an incorrect algorithm. Expected RS256 but got HS256.'
        assert str(excinfo.value) == expected
    