# Copyright 2026 Google Inc.
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

"""Integration tests for firebase_admin.dataconnect module (execute_graphql)."""

import pytest

from firebase_admin import dataconnect, exceptions

CONNECTOR_CONFIG = dataconnect.ConnectorConfig(
    location='us-east4',
    service_id='my-service',
    connector='my-connector'
)


FRED_USER = {'id': 'fred_id', 'address': '32 Elm St.', 'name': 'Fred'}
FREDRICK_USER = {
    'id': FRED_USER['id'],
    'address': '64 Elm St. North',
    'name': 'Fredrick'
}
JEFF_USER = {'id': 'jeff_id', 'address': '99 Oak St.', 'name': 'Jeff'}

FRED_EMAIL = {
    'id': 'email_id',
    'subject': 'free bitcoin inside',
    'date': '1999-12-31',
    'text': 'get pranked! LOL!',
    'from': {'id': FRED_USER['id']}
}

INITIAL_STATE = {
    'users': [FRED_USER, JEFF_USER],
    'emails': [FRED_EMAIL]
}

# Queries & Mutations
QUERY_LIST_USERS = (
    'query ListUsers @auth(level: PUBLIC) { users { id, name, address } }'
)
QUERY_LIST_EMAILS = (
    'query ListEmails @auth(level: NO_ACCESS) '
    '{ emails { id subject text date from { id } } }'
)
QUERY_GET_EMAIL = (
    'query GetEmail($id: String!) @auth(level: NO_ACCESS) '
    '{ email(id: $id) { id subject text date from { id } } }'
)
QUERY_GET_USER_BY_ID = (
    'query GetUser($id: User_Key!) { user(key: $id) { id name address } }'
)

QUERY_LIST_USERS_IMPERSONATION = """
    query ListUsers @auth(level: USER) {
      users(where: { id: { eq_expr: "auth.uid" } }) { id, name, address }
    }"""

MULTIPLE_QUERIES = f"{QUERY_LIST_USERS}\n{QUERY_LIST_EMAILS}"

UPSERT_FRED_USER = f"""
    mutation user {{
      user_upsert(data: {{id: "{FRED_USER['id']}", address: "{FRED_USER['address']}", name: "{FRED_USER['name']}"}})
    }}"""

UPDATE_FREDRICK_USER_IMPERSONATED = f"""
    mutation upsertFredrickUserImpersonated @auth(level: USER) {{
      user_update(
        key: {{ id_expr: "auth.uid" }},
        data: {{ address: "{FREDRICK_USER['address']}", name: "{FREDRICK_USER['name']}" }}
      )
    }}"""

UPSERT_JEFF_USER = f"""
    mutation user {{
      user_upsert(data: {{id: "{JEFF_USER['id']}", address: "{JEFF_USER['address']}", name: "{JEFF_USER['name']}"}})
    }}"""

UPSERT_FRED_EMAIL = f"""
    mutation email {{
      email_upsert(data: {{
        id:"{FRED_EMAIL['id']}",
        subject: "{FRED_EMAIL['subject']}",
        date: "{FRED_EMAIL['date']}",
        text: "{FRED_EMAIL['text']}",
        fromId: "{FRED_EMAIL['from']['id']}"
      }})
    }}"""

DELETE_ALL = """
    mutation delete {
      email_deleteMany(all: true)
      user_deleteMany(all: true)
    }"""

# Impersonation Options
OPTS_UNAUTHORIZED_CLAIMS = dataconnect.GraphqlOptions(
    impersonate=dataconnect.Impersonation.unauthenticated()
)

OPTS_AUTHORIZED_FRED_CLAIMS = dataconnect.GraphqlOptions(
    impersonate=dataconnect.Impersonation.authenticated({
        'sub': FRED_USER['id']
    })
)

OPTS_NON_EXISTING_CLAIMS = dataconnect.GraphqlOptions(
    impersonate=dataconnect.Impersonation.authenticated({
        'sub': 'non-existing-id',
        'email_verified': True
    })
)


class TestExecuteGraphql:
    """Integration tests for execute_graphql method."""

    def test_execute_graphql_mutation(self):
        """Tests executing mutations via execute_graphql."""
        dc_client = dataconnect.client(CONNECTOR_CONFIG)
        fred_resp = dc_client.execute_graphql(UPSERT_FRED_USER)
        assert fred_resp.data['user_upsert']['id'] == FRED_USER['id']

        jeff_resp = dc_client.execute_graphql(UPSERT_JEFF_USER)
        assert jeff_resp.data['user_upsert']['id'] == JEFF_USER['id']

        upsert_email_resp = dc_client.execute_graphql(UPSERT_FRED_EMAIL)
        email_id = upsert_email_resp.data['email_upsert']['id']
        assert email_id

        get_email_options = dataconnect.GraphqlOptions(variables={'id': email_id})
        query_email_resp = dc_client.execute_graphql(
            QUERY_GET_EMAIL, options=get_email_options
        )
        assert query_email_resp.data['email'] == FRED_EMAIL


    def test_execute_graphql_query(self):
        """Tests executing a query via execute_graphql."""
        dc_client = dataconnect.client(CONNECTOR_CONFIG)
        resp = dc_client.execute_graphql(QUERY_LIST_USERS)
        assert sorted(resp.data['users'], key=lambda x: x['id']) == sorted(
            INITIAL_STATE['users'], key=lambda x: x['id']
        )

    def test_execute_graphql_operation_name_multiple_queries(self):
        """Tests operation_name with multi-query document."""
        dc_client = dataconnect.client(CONNECTOR_CONFIG)
        options = dataconnect.GraphqlOptions(operation_name='ListEmails')
        resp = dc_client.execute_graphql(MULTIPLE_QUERIES, options=options)
        assert resp.data['emails'] == INITIAL_STATE['emails']

    def test_execute_graphql_query_error_missing_variables(self):
        """Tests query error when required variables are missing."""
        dc_client = dataconnect.client(CONNECTOR_CONFIG)
        with pytest.raises(dataconnect.QueryError) as excinfo:
            dc_client.execute_graphql(QUERY_GET_USER_BY_ID)
        assert excinfo.value.code == 'query-error'

    def test_execute_graphql_query_with_variables(self):
        """Tests query execution with variables."""
        dc_client = dataconnect.client(CONNECTOR_CONFIG)
        user_id = INITIAL_STATE['users'][0]['id']
        options = dataconnect.GraphqlOptions(variables={'id': {'id': user_id}})
        resp = dc_client.execute_graphql(QUERY_GET_USER_BY_ID, options=options)
        assert resp.data['user'] == INITIAL_STATE['users'][0]


class TestExecuteGraphqlRead:
    """Integration tests for execute_graphql_read method."""

    def test_execute_graphql_read_query(self):
        """Tests read-only query execution."""
        dc_client = dataconnect.client(CONNECTOR_CONFIG)
        resp = dc_client.execute_graphql_read(QUERY_LIST_USERS)
        assert sorted(resp.data['users'], key=lambda x: x['id']) == sorted(
            INITIAL_STATE['users'], key=lambda x: x['id']
        )


    def test_execute_graphql_read_mutation_fails(self):
        """Tests that execute_graphql_read rejects mutation queries."""
        dc_client = dataconnect.client(CONNECTOR_CONFIG)
        with pytest.raises(exceptions.PermissionDeniedError):
            dc_client.execute_graphql_read(UPSERT_FRED_USER)


class TestExecuteGraphqlImpersonation:
    """Integration tests for execute_graphql / execute_graphql_read impersonation."""

    class TestUserAuthPolicy:
        """Integration tests for @auth(level: USER) policy."""

        def test_execute_graphql_read_impersonated_authenticated(self):
            """Tests read query with authenticated impersonation."""
            dc_client = dataconnect.client(CONNECTOR_CONFIG)
            resp = dc_client.execute_graphql_read(
                QUERY_LIST_USERS_IMPERSONATION, options=OPTS_AUTHORIZED_FRED_CLAIMS
            )
            assert len(resp.data['users']) == 1
            assert resp.data['users'][0] == FRED_USER

        def test_execute_graphql_read_impersonated_unauthenticated_fails(self):
            """Tests read query with unauthenticated impersonation fails."""
            dc_client = dataconnect.client(CONNECTOR_CONFIG)
            with pytest.raises(exceptions.UnauthenticatedError):
                dc_client.execute_graphql_read(
                    QUERY_LIST_USERS_IMPERSONATION, options=OPTS_UNAUTHORIZED_CLAIMS
                )

        def test_execute_graphql_impersonated_authenticated(self):
            """Tests query with authenticated impersonation."""
            dc_client = dataconnect.client(CONNECTOR_CONFIG)
            resp = dc_client.execute_graphql(
                QUERY_LIST_USERS_IMPERSONATION, options=OPTS_AUTHORIZED_FRED_CLAIMS
            )
            assert len(resp.data['users']) == 1
            assert resp.data['users'][0] == FRED_USER

        def test_execute_graphql_impersonated_unauthenticated_fails(self):
            """Tests query with unauthenticated impersonation fails."""
            dc_client = dataconnect.client(CONNECTOR_CONFIG)
            with pytest.raises(exceptions.UnauthenticatedError):
                dc_client.execute_graphql(
                    QUERY_LIST_USERS_IMPERSONATION, options=OPTS_UNAUTHORIZED_CLAIMS
                )

        def test_execute_graphql_impersonated_non_existing_claims(self):
            """Tests query with non-existing user claims returns empty list."""
            dc_client = dataconnect.client(CONNECTOR_CONFIG)
            resp = dc_client.execute_graphql(
                QUERY_LIST_USERS_IMPERSONATION, options=OPTS_NON_EXISTING_CLAIMS
            )
            assert resp.data['users'] == []

        def test_execute_graphql_impersonated_mutation_authenticated(self):
            """Tests mutation with authenticated impersonation."""
            dc_client = dataconnect.client(CONNECTOR_CONFIG)
            update_resp = dc_client.execute_graphql(
                UPDATE_FREDRICK_USER_IMPERSONATED, options=OPTS_AUTHORIZED_FRED_CLAIMS
            )
            assert update_resp.data['user_update']['id'] == FRED_USER['id']

            user_id = FRED_USER['id']
            query_options = dataconnect.GraphqlOptions(variables={'id': {'id': user_id}})
            query_resp = dc_client.execute_graphql(QUERY_GET_USER_BY_ID, options=query_options)
            assert query_resp.data['user'] == FREDRICK_USER
            dc_client.execute_graphql(UPSERT_FRED_USER)

        def test_execute_graphql_impersonated_mutation_unauthenticated_fails(self):
            """Tests mutation with unauthenticated impersonation fails."""
            dc_client = dataconnect.client(CONNECTOR_CONFIG)
            with pytest.raises(exceptions.UnauthenticatedError):
                dc_client.execute_graphql(
                    UPDATE_FREDRICK_USER_IMPERSONATED, options=OPTS_UNAUTHORIZED_CLAIMS
                )

        def test_execute_graphql_impersonated_mutation_non_existing_claims(self):
            """Tests mutation with non-existing claims returns None."""
            dc_client = dataconnect.client(CONNECTOR_CONFIG)
            resp = dc_client.execute_graphql(
                UPDATE_FREDRICK_USER_IMPERSONATED, options=OPTS_NON_EXISTING_CLAIMS
            )
            assert resp.data['user_update'] is None

    class TestPublicAuthPolicy:
        """Integration tests for @auth(level: PUBLIC) policy."""

        def test_impersonated_authenticated(self):
            """Tests public query with authenticated claims."""
            dc_client = dataconnect.client(CONNECTOR_CONFIG)
            resp = dc_client.execute_graphql(
                QUERY_LIST_USERS, options=OPTS_AUTHORIZED_FRED_CLAIMS
            )
            assert sorted(resp.data['users'], key=lambda x: x['id']) == sorted(
                INITIAL_STATE['users'], key=lambda x: x['id']
            )

        def test_impersonated_unauthenticated(self):
            """Tests public query with unauthenticated claims."""
            dc_client = dataconnect.client(CONNECTOR_CONFIG)
            resp = dc_client.execute_graphql(
                QUERY_LIST_USERS, options=OPTS_UNAUTHORIZED_CLAIMS
            )
            assert sorted(resp.data['users'], key=lambda x: x['id']) == sorted(
                INITIAL_STATE['users'], key=lambda x: x['id']
            )

        def test_impersonated_non_existing_claims(self):
            """Tests public query with non-existing user claims."""
            dc_client = dataconnect.client(CONNECTOR_CONFIG)
            resp = dc_client.execute_graphql(
                QUERY_LIST_USERS, options=OPTS_NON_EXISTING_CLAIMS
            )
            assert sorted(resp.data['users'], key=lambda x: x['id']) == sorted(
                INITIAL_STATE['users'], key=lambda x: x['id']
            )


    class TestNoAccessAuthPolicy:
        """Integration tests for @auth(level: NO_ACCESS) policy."""

        def test_impersonated_authenticated_fails(self):
            """Tests no-access query with authenticated claims fails."""
            dc_client = dataconnect.client(CONNECTOR_CONFIG)
            with pytest.raises(exceptions.PermissionDeniedError):
                dc_client.execute_graphql(
                    QUERY_LIST_EMAILS, options=OPTS_AUTHORIZED_FRED_CLAIMS
                )

        def test_impersonated_unauthenticated_fails(self):
            """Tests no-access query with unauthenticated claims fails."""
            dc_client = dataconnect.client(CONNECTOR_CONFIG)
            with pytest.raises(exceptions.PermissionDeniedError):
                dc_client.execute_graphql(
                    QUERY_LIST_EMAILS, options=OPTS_UNAUTHORIZED_CLAIMS
                )

        def test_impersonated_non_existing_claims_fails(self):
            """Tests no-access query with non-existing user claims fails."""
            dc_client = dataconnect.client(CONNECTOR_CONFIG)
            with pytest.raises(exceptions.PermissionDeniedError):
                dc_client.execute_graphql(
                    QUERY_LIST_EMAILS, options=OPTS_NON_EXISTING_CLAIMS
                )
