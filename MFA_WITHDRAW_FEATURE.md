# MFA Withdraw Feature Implementation

This document describes the implementation of the `withdraw_mfa_enrollment` feature for the Firebase Admin SDK for Python.

## Overview

The `withdraw_mfa_enrollment` function allows administrators to programmatically withdraw (reset) a user's enrolled second factor authentication method. This feature was previously available in the Node.js SDK but missing from the Python SDK.

## Implementation Details

### Files Modified/Created

1. **`firebase_admin/_mfa.py`** - New module containing the core MFA functionality
2. **`firebase_admin/auth.py`** - Updated to export the new function and MfaError
3. **`tests/test_mfa_withdraw.py`** - Comprehensive test suite

### Key Components

#### Core Function: `withdraw_mfa_enrollment`

```python
def withdraw_mfa_enrollment(
    uid: str, 
    mfa_enrollment_id: str, 
    api_key: str, 
    tenant_id: str | None = None, 
    app=None
) -> dict:
```

**Parameters:**
- `uid`: Firebase Auth UID of the user
- `mfa_enrollment_id`: The MFA enrollment ID to revoke
- `api_key`: Web API key from Firebase project settings
- `tenant_id`: Optional tenant ID for multi-tenancy
- `app`: Optional Firebase app instance

**Returns:** Dictionary response from the Identity Toolkit API

**Raises:**
- `MfaError`: If the operation fails
- `ValueError`: For invalid arguments

#### Implementation Flow

1. **Create Custom Token**: Uses the Firebase Admin SDK to mint a custom token for the user
2. **Exchange for ID Token**: Calls the Identity Toolkit `signInWithCustomToken` endpoint
3. **Withdraw MFA**: Uses the ID token to call the `mfaEnrollment:withdraw` endpoint

#### Error Handling

- Custom `MfaError` exception for MFA-specific failures
- Proper HTTP error handling with detailed error messages
- Input validation for required parameters

## Usage Example

```python
import firebase_admin
from firebase_admin import auth, credentials

# Initialize the SDK
cred = credentials.Certificate("service-account-key.json")
firebase_admin.initialize_app(cred)

# Withdraw MFA enrollment
try:
    result = auth.withdraw_mfa_enrollment(
        uid="user123",
        mfa_enrollment_id="enrollment456", 
        api_key="your-web-api-key"
    )
    print("MFA withdrawn successfully:", result)
except auth.MfaError as e:
    print("MFA operation failed:", e)
```

## Testing

The implementation includes comprehensive tests covering:
- Successful withdrawal scenarios
- Error handling for API failures
- Input validation
- Integration with the auth module

Run tests with:
```bash
python -m pytest tests/test_mfa_withdraw.py -v
```

## API Compatibility

This implementation follows the same pattern as the Node.js SDK, ensuring consistency across Firebase Admin SDKs.

## Next Steps

1. **Integration Testing**: Test with actual Firebase project
2. **Documentation**: Add to official SDK documentation
3. **Code Review**: Submit for Firebase team review
4. **Release**: Include in next SDK version

## Notes

- Requires Web API key (different from service account key)
- Uses Identity Toolkit v2 API endpoints
- Supports multi-tenant projects via `tenant_id` parameter
- Follows existing SDK patterns for error handling and app management