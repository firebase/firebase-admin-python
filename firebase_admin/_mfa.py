# Copyright 2025 Google Inc.
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

"""Firebase auth MFA management sub module."""

import requests
import typing as _t

from firebase_admin import _auth_client
from firebase_admin import _utils
from firebase_admin import exceptions

_AUTH_ATTRIBUTE = '_auth'

class MfaError(exceptions.FirebaseError):
    """Represents an error related to MFA operations."""
    def __init__(self, message, cause=None, http_response=None):
        exceptions.FirebaseError.__init__(self, 'MFA_ERROR', message, cause, http_response)

def _to_text(b: _t.Union[str, bytes]) -> str:
    return b.decode("utf-8") if isinstance(b, (bytes, bytearray)) else str(b)


def _signin_with_custom_token(*, api_key: str, custom_token: str, tenant_id: str | None) -> str:
    """
    Exchange a Custom Token for an ID token.

    Uses: POST https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=API_KEY
    """
    if not api_key:
        raise ValueError("api_key must be provided (Web API key from Firebase project settings).")

    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key={api_key}"
    payload = {
        "token": custom_token,
        "returnSecureToken": True,
    }
    if tenant_id:
        payload["tenantId"] = tenant_id

    try:
        r = requests.post(url, json=payload, timeout=30)
        r.raise_for_status()
        data = r.json()
        if "idToken" not in data:
            raise MfaError(f"Failed to exchange custom token for ID token: {data.get('error', 'Unknown error')}", http_response=r)
        return data["idToken"]
    except requests.exceptions.RequestException as e:
        message = f"Failed to exchange custom token for ID token: {e}"
        raise MfaError(message, cause=e, http_response=e.response) from e


def withdraw_mfa_enrollment(
    *,
    uid: str,
    mfa_enrollment_id: str,
    api_key: str,
    tenant_id: str | None = None,
    app=None,
) -> dict:
    """
    Withdraw (reset) a user's enrolled second factor by enrollment ID.

    Args:
        uid:           Firebase Auth UID of the user to act on.
        mfa_enrollment_id: Enrollment ID of the second factor to revoke.
        api_key:       Web API key (from Firebase console) used by signInWithCustomToken.
        tenant_id:     Optional Tenant ID if using multi-tenancy.
        app:           Optional firebase_admin App instance.

    Returns:
        dict response from accounts.mfaEnrollment:withdraw (typically contains updated user info).

    Raises:
        MfaError on failure.
    """
    if not uid:
        raise ValueError("uid must be a non-empty string.")
    if not mfa_enrollment_id:
        raise ValueError("mfa_enrollment_id must be a non-empty string.")

    # 1) Create Custom Token as the user
    client = _utils.get_app_service(app, _AUTH_ATTRIBUTE, _auth_client.Client)
    custom_token = _to_text(client.create_custom_token(uid))

    # 2) Exchange Custom Token → ID token (requires API key)
    id_token = _signin_with_custom_token(api_key=api_key, custom_token=custom_token, tenant_id=tenant_id)

    # 3) Withdraw MFA with the ID token
    withdraw_url = "https://identitytoolkit.googleapis.com/v2/accounts/mfaEnrollment:withdraw"
    if api_key:
        withdraw_url += f"?key={api_key}"  # optional, but fine to append

    payload = {"idToken": id_token, "mfaEnrollmentId": mfa_enrollment_id}
    if tenant_id:
        payload["tenantId"] = tenant_id

    try:
        r = requests.post(withdraw_url, json=payload, timeout=30)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        message = f"Failed to withdraw MFA enrollment: {e}"
        raise MfaError(message, cause=e, http_response=e.response) from e
