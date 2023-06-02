import firebase_admin.
import json

cred = credentials.Certificate(
    "/Users/pragatimodi/Downloads/test-project-pragatimodi-9ce7c-firebase-adminsdk-4ep8c-c8769574dc.json")
firebase_admin.initialize_app(cred)

# display_name="Test-App-Tenant"
# mfa_config = {
# "state": "ENABLED",
# "factorIds": ['PHONE_SMS'],
# "providerConfigs": [
#     {
#         "state": "ENABLED",
#         "totpProviderConfig": {
#             "adjacentIntervals": 5,
#         },
#     },
# ],
# }

# tenant = tenant_mgt.Tenant(x)
# created_tenant = tenant_mgt.get_tenant(tenant_id="Test-App-Tenant-691a0")
# print(json.dumps(created_tenant.__dict__))

# user_record = {
# #     ""
# }

user = auth.create_user(
    email="abc@user-test.com",
    display_name='Random User',
    photo_url='https://example.com/photo.png',
    email_verified=True,
    password='secret',
    multi_factor_settings=MultiFactorSettings)

# print(user)

# user_record = auth.get_user_by_email(email="abc@user-test.com")
# print(json.dumps(user_record.__dict__))
