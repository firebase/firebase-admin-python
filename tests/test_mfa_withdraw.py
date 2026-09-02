# tests/test_mfa_withdraw.py
from unittest import mock
import pytest
import firebase_admin
from firebase_admin import auth
from firebase_admin._mfa import withdraw_mfa_enrollment, MfaError
from tests import testutils

API_KEY = "fake-api-key"
UID = "uid123"
ENROLL_ID = "enroll123"

@pytest.fixture(scope='module')
def mfa_app():
    app = firebase_admin.initialize_app(
        testutils.MockCredential(), name='mfaTest', options={'projectId': 'mock-project-id'})
    yield app
    firebase_admin.delete_app(app)

def _fake_custom_token(uid):
    return b"FAKE.CUSTOM.TOKEN"

@mock.patch("firebase_admin._auth_client.Client.create_custom_token", side_effect=_fake_custom_token)
@mock.patch("firebase_admin._mfa.requests.post")
def test_withdraw_success(mock_post, _, mfa_app):
    # 1st call: signInWithCustomToken -> returns idToken
    # 2nd call: withdraw -> returns ok
    mock_post.side_effect = [
        mock.Mock(status_code=200, json=lambda: {"idToken": "ID.TOKEN"}),
        mock.Mock(status_code=200, json=lambda: {"localId": UID}),
    ]
    res = withdraw_mfa_enrollment(uid=UID, mfa_enrollment_id=ENROLL_ID, api_key=API_KEY, app=mfa_app)
    assert res["localId"] == UID
    assert mock_post.call_count == 2

@mock.patch("firebase_admin._auth_client.Client.create_custom_token", side_effect=_fake_custom_token)
@mock.patch("firebase_admin._mfa.requests.post")
def test_withdraw_signin_fail(mock_post, _, mfa_app):
    mock_post.return_value = mock.Mock(status_code=400, json=lambda: {"error": {"message": "INVALID_CUSTOM_TOKEN"}})
    with pytest.raises(MfaError):
        withdraw_mfa_enrollment(uid=UID, mfa_enrollment_id=ENROLL_ID, api_key=API_KEY, app=mfa_app)

@mock.patch("firebase_admin._auth_client.Client.create_custom_token", side_effect=_fake_custom_token)
@mock.patch("firebase_admin._mfa.requests.post")
def test_withdraw_via_auth_module(mock_post, _, mfa_app):
    """Test that the function is accessible via the auth module."""
    mock_post.side_effect = [
        mock.Mock(status_code=200, json=lambda: {"idToken": "ID.TOKEN"}),
        mock.Mock(status_code=200, json=lambda: {"localId": UID}),
    ]
    res = auth.withdraw_mfa_enrollment(uid=UID, mfa_enrollment_id=ENROLL_ID, api_key=API_KEY, app=mfa_app)
    assert res["localId"] == UID
    assert mock_post.call_count == 2

def test_invalid_arguments():
    """Test that invalid arguments raise ValueError."""
    with pytest.raises(ValueError, match="uid must be a non-empty string"):
        withdraw_mfa_enrollment(uid="", mfa_enrollment_id=ENROLL_ID, api_key=API_KEY)
    
    with pytest.raises(ValueError, match="mfa_enrollment_id must be a non-empty string"):
        withdraw_mfa_enrollment(uid=UID, mfa_enrollment_id="", api_key=API_KEY)