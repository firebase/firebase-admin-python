# Copyright 2025 Google LLC
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

"""Pipeline snippets for Cloud Firestore."""

# pylint: disable=invalid-name


def load_test_data(db):
    # [START pipeline_join_test_data]
    # Load set of cities.
    cities = db.collection("cities")

    cities.document("SF").set(
        {
            "name": "San Francisco",
            "state": "CA",
            "country": "USA",
        }
    )
    cities.document("LA").set(
        {
            "name": "Los Angeles",
            "state": "CA",
            "country": "USA",
        }
    )
    cities.document("DC").set(
        {
            "name": "Washington, D.C.",
            "state": None,
            "country": "USA",
        }
    )
    cities.document("TOK").set(
        {
            "name": "Tokyo",
            "state": None,
            "country": "Japan",
        }
    )

    # Load restaurants in various cities.
    sf_restaurants = db.collection("cities").document("SF").collection("restaurants")
    la_restaurants = db.collection("cities").document("LA").collection("restaurants")
    dc_restaurants = db.collection("cities").document("DC").collection("restaurants")

    rest1 = sf_restaurants.add(
        {
            "name": "Golden Gate Pizza",
            "type": "pizza",
            "owner_id": "Mario Rossi",
        }
    )[1]
    rest2 = sf_restaurants.add(
        {
            "name": "Bay Area Burger",
            "type": "burger",
            "owner_id": "Sarah Jenkins",
        }
    )[1]
    rest3 = sf_restaurants.add(
        {
            "name": "Sunset Taco",
            "type": "mexican",
            "owner_id": "Edward",
        }
    )[1]

    rest4 = la_restaurants.add(
        {
            "name": "Hollywood Sushi",
            "type": "sushi",
            "owner_id": "Ken Kenji",
        }
    )[1]
    rest5 = la_restaurants.add(
        {
            "name": "Venice Pizza",
            "type": "pizza",
            "owner_id": "Luigi Romano",
        }
    )[1]

    rest6 = dc_restaurants.add(
        {
            "name": "Capitol Tacos",
            "type": "mexican",
            "owner_id": "Maria Garcia",
        }
    )[1]
    rest7 = dc_restaurants.add(
        {
            "name": "Georgetown Coffee",
            "type": "cafe",
            "owner_id": "David Kim",
        }
    )[1]

    # Load collection of reviews.
    reviews = db.collection("reviews")

    reviews.add({"restaurant": rest1, "rating": 5, "reviewer_id": "Alice"})
    reviews.add({"restaurant": rest1, "rating": 4, "reviewer_id": "Bob"})
    reviews.add({"restaurant": rest2, "rating": 4, "reviewer_id": "Charlie"})
    reviews.add({"restaurant": rest3, "rating": 5, "reviewer_id": "Diana"})
    reviews.add({"restaurant": rest3, "rating": 4, "reviewer_id": "Edward"})
    reviews.add({"restaurant": rest3, "rating": 4, "reviewer_id": "Fiona"})
    # rest4 has 0 reviews
    reviews.add({"restaurant": rest5, "rating": 3, "reviewer_id": "George"})
    reviews.add({"restaurant": rest6, "rating": 5, "reviewer_id": "Hannah"})
    reviews.add({"restaurant": rest6, "rating": 4, "reviewer_id": "Ian"})
    reviews.add({"restaurant": rest7, "rating": 5, "reviewer_id": "Julia"})
    # [END pipeline_join_test_data]


def pipeline_join_lookup(db):
    from google.cloud.firestore_v1.pipeline_expressions import Field, Variable

    # [START pipeline_join_lookup]
    results = (
        db.pipeline()
        .collection_group("reviews")
        .define(Field.of("restaurant").as_("restaurant_name"))
        .add_fields(
            db.pipeline()
            .collection_group("restaurants")
            .where(Field.of("__name__").equal(Variable("restaurant_name")))
            .select("name", "type")
            .to_scalar_expression()
            .as_("restaurant")
        )
        .execute()
    )
    # [END pipeline_join_lookup]
    return results


def pipeline_join_array(db):
    from google.cloud.firestore_v1.pipeline_expressions import Field, Variable

    # [START pipeline_join_array]
    results = (
        db.pipeline()
        .collection_group("restaurants")
        .where(Field.of("type").equal("pizza"))
        .define(Field.of("__name__").as_("restaurant_name"))
        .select(
            Field.of("name"),
            db.pipeline()
            .collection_group("reviews")
            .where(Field.of("restaurant").equal(Variable("restaurant_name")))
            .select("rating", "reviewer_id")
            .to_array_expression()
            .as_("reviews"),
        )
        .execute()
    )
    # [END pipeline_join_array]
    return results


def pipeline_join_aggregate(db):
    from google.cloud.firestore_v1.pipeline_expressions import Field, Variable

    # [START pipeline_join_aggregate]
    results = (
        db.pipeline()
        .collection_group("restaurants")
        .where(Field.of("type").equal("pizza"))
        .define(Field.of("__name__").as_("restaurant_name"))
        .select(
            Field.of("name"),
            db.pipeline()
            .collection_group("reviews")
            .where(Field.of("restaurant").equal(Variable("restaurant_name")))
            .aggregate(Field.of("rating").average().as_("avg_rating"))
            .to_scalar_expression()
            .as_("avg_rating"),
        )
        .execute()
    )
    # [END pipeline_join_aggregate]
    return results


def pipeline_join_limit(db):
    from google.cloud.firestore_v1.pipeline_expressions import Field, Variable

    # [START pipeline_join_limit]
    results = (
        db.pipeline()
        .collection_group("restaurants")
        .define(Field.of("__name__").as_("restaurant_name"))
        .select(
            Field.of("name"),
            db.pipeline()
            .collection_group("reviews")
            .where(Field.of("restaurant").equal(Variable("restaurant_name")))
            .sort(Field.of("rating").descending())
            .limit(2)
            .select("rating", "reviewer_id")
            .to_array_expression()
            .as_("top_reviews"),
        )
        .execute()
    )
    # [END pipeline_join_limit]
    return results


def pipeline_join_subcollection(db):
    from google.cloud.firestore_v1.pipeline_source import PipelineSource

    # [START pipeline_join_subcollection]
    results = (
        db.pipeline()
        .collection("cities")
        .add_fields(
            PipelineSource.subcollection("restaurants")
            .to_array_expression()
            .length()
            .as_("restaurant_count")
        )
        .execute()
    )
    # [END pipeline_join_subcollection]
    return results


def pipeline_join_multi_field(db):
    from google.cloud.firestore_v1.pipeline_expressions import Count, Field, Variable

    # [START pipeline_join_multi_field]
    results = (
        db.pipeline()
        .collection_group("restaurants")
        .define(
            Field.of("owner_id").as_("owner_id"),
            Field.of("__name__").as_("__name__"),
        )
        .where(
            db.pipeline()
            .collection_group("reviews")
            .where(Field.of("restaurant").equal(Variable("__name__")))
            .where(Field.of("reviewer_id").equal(Variable("owner_id")))
            .aggregate(Count().as_("c"))
            .to_scalar_expression()
            .greater_than(0)
        )
        .execute()
    )
    # [END pipeline_join_multi_field]
    return results


def pipeline_join_anti(db):
    from google.cloud.firestore_v1.pipeline_expressions import Count, Field, Variable

    # [START pipeline_join_anti]
    results = (
        db.pipeline()
        .collection_group("restaurants")
        .define(Field.of("__name__").as_("restaurant_name"))
        .where(
            db.pipeline()
            .collection_group("reviews")
            .where(Field.of("restaurant").equal(Variable("restaurant_name")))
            .aggregate(Count().as_("review_count"))
            .to_scalar_expression()
            .equal(0)
        )
        .execute()
    )
    # [END pipeline_join_anti]
    return results


def pipeline_join_unnest(db):
    from google.cloud.firestore_v1.pipeline_expressions import Field, Variable

    # [START pipeline_join_unnest]
    results = (
        db.pipeline()
        .collection_group("restaurants")
        .where(Field.of("type").equal("pizza"))
        .define(Field.of("__name__").as_("restaurant_name"))
        .unnest(
            db.pipeline()
            .collection_group("reviews")
            .where(Field.of("restaurant").equal(Variable("restaurant_name")))
            .select("rating", "reviewer_id")
            .to_array_expression(),
            alias="review",
        )
        .execute()
    )
    # [END pipeline_join_unnest]
    return results


def pipeline_join_uncorrelated(db):
    from google.cloud.firestore_v1.pipeline_expressions import Field

    # [START pipeline_join_uncorrelated]
    results = (
        db.pipeline()
        .collection("reviews")
        # Average review rating is 4.3
        .where(
            Field.of("rating").greater_than(
                db.pipeline()
                .collection("reviews")
                .aggregate(Field.of("rating").average().as_("avg"))
                .to_scalar_expression()
            )
        )
        .select("rating", "reviewer_id")
        .execute()
    )
    # [END pipeline_join_uncorrelated]
    return results


def pipeline_force_table_scan(db):
    # [START pipeline_force_table_scan]
    # Force Planner to only do a Full-Table Scan
    results = (
        db.pipeline()
        .collection_group("customers")
        .limit(100)
        .execute()
    )
    # [END pipeline_force_table_scan]
    return results


def literals_example(db):
    from google.cloud.firestore_v1.pipeline_expressions import Field

    # [START literals_example]
    results = (
        db.pipeline()
        .literals(
            {"name": "joe", "age": 10},
            {"name": "bob", "age": 30},
            {"name": "alice", "age": 40},
        )
        .where(Field.of("age").less_than(35))
        .execute()
    )
    # [END literals_example]
    return results


def literals_expressions(db):
    from google.cloud.firestore_v1.pipeline_expressions import (
        Array,
        Constant,
        Field,
        Map,
    )

    # [START literals_expressions]
    results = (
        db.pipeline()
        .literals(
            {
                "item": "Book",
                "price": 25,
                "quantity": 2,
                "details": Map({"category": Constant.of("Reading")}),
            },
            {
                "item": "Pen",
                "price": 5,
                "quantity": 10,
                "tags": Array(["office", "writing"]),
            },
        )
        .select(
            Field.of("item"),
            Field.of("price").multiply(Field.of("quantity")).as_("total"),
        )
        .execute()
    )
    # [END literals_expressions]
    return results


def update_dml(db):
    from google.cloud.firestore_v1.pipeline_expressions import Field

    # [START update_dml]
    results = (
        db.pipeline()
        .collection("books")
        .where(Field.of("price").less_than(50))
        .update(Field.of("price").multiply(0.5).as_("price"))
        .execute()
    )
    # [END update_dml]
    return results


def delete_dml(db):
    from google.cloud.firestore_v1.pipeline_expressions import Field

    # [START delete_dml]
    results = (
        db.pipeline()
        .collection("books")
        .where(Field.of("status").equal("discontinued"))
        .delete()
        .execute()
    )
    # [END delete_dml]
    return results


def delete_full_collection(db):
    # [START delete_full_collection]
    results = db.pipeline().collection("logs").delete().execute()
    # [END delete_full_collection]
    return results


def dml_transaction(db):
    from google.cloud import firestore
    from google.cloud.firestore_v1.pipeline_expressions import Constant, Field

    # [START dml_transaction]
    @firestore.transactional
    def update_in_transaction(transaction):
        db.pipeline().collection("inventory").where(
            Field.of("stock").less_than(0)
        ).update(Constant.of(0).as_("stock")).execute(transaction=transaction)

    transaction = db.transaction()
    update_in_transaction(transaction)
    # [END dml_transaction]


def dml_atomic_option(db):
    from google.cloud.firestore_v1.pipeline_expressions import Constant, Field

    # [START dml_atomic_option]
    results = (
        db.pipeline()
        .collection("users")
        .where(Field.of("status").equal("pending"))
        .update(Constant.of("active").as_("status"))
        .execute(additional_options={"atomic": Constant.of(True)})
    )
    # [END dml_atomic_option]
    return results


def insert_static_documents(db):
    from google.cloud.firestore_v1.pipeline_expressions import Constant

    # [START insert_static_documents]
    results = (
        db.pipeline()
        .literals(
            {"name": "San Francisco", "state": "CA", "country": "USA"},
            {"name": "Los Angeles", "state": "CA", "country": "USA"},
        )
        .raw_stage("insert", options={"collection": Constant.of("cities")})
        .execute()
    )
    # [END insert_static_documents]
    return results


def insert_evaluated_doc_id(db):
    from google.cloud.firestore_v1.pipeline_expressions import Constant, Field

    # [START insert_evaluated_doc_id]
    results = (
        db.pipeline()
        .literals(
            {"name": "San Francisco", "state": "CA", "country": "USA"},
            {"name": "Los Angeles", "state": "CA", "country": "USA"},
        )
        .raw_stage(
            "insert",
            options={
                "collection": Constant.of("cities"),
                "document_id": Field.of("country")
                .to_upper()
                .concat("-", Field.of("state"), "-", Field.of("name")),
            },
        )
        .execute()
    )
    # [END insert_evaluated_doc_id]
    return results


def insert_document_references(db):
    # [START insert_document_references]
    results = (
        db.pipeline()
        .literals(
            {
                "__name__": db.collection("cities").document("SF"),
                "name": "San Francisco",
            }
        )
        .raw_stage("insert")
        .execute()
    )
    # [END insert_document_references]
    return results


def insert_auto_generated_ids(db):
    from google.cloud.firestore_v1.pipeline_expressions import (
        Constant,
        FunctionExpression,
    )

    # [START insert_auto_generated_ids]
    results = (
        db.pipeline()
        .literals(
            {"name": "San Francisco"},
            {"name": "Los Angeles"},
        )
        .raw_stage(
            "insert",
            options={
                "collection": Constant.of("cities"),
                "document_id": FunctionExpression("auto_id", []),
            },
        )
        .execute()
    )
    # [END insert_auto_generated_ids]
    return results


def insert_subcollection(db):
    from google.cloud.firestore_v1.pipeline_expressions import Constant

    # [START insert_subcollection]
    results = (
        db.pipeline()
        .literals(
            {"title": "Buy groceries"},
            {"title": "Clean house"},
        )
        .raw_stage(
            "insert",
            options={"collection": Constant.of("users/user_a/tasks")},
        )
        .execute()
    )
    # [END insert_subcollection]
    return results


def insert_different_collection(db):
    from google.cloud.firestore_v1.pipeline_expressions import Constant, Field

    # [START insert_different_collection]
    results = (
        db.pipeline()
        .collection("users")
        .raw_stage(
            "insert",
            options={
                "collection": Constant.of("users_backup"),
                "document_id": Field.of("__name__").document_id(),
            },
        )
        .execute()
    )
    # [END insert_different_collection]
    return results


def insert_advanced_queries(db):
    from google.cloud.firestore_v1.pipeline_expressions import Constant, Field

    # [START insert_advanced_queries]
    results = (
        db.pipeline()
        .collection("products")
        .raw_stage("search", options={"query": Constant.of("shoes")})
        .sort(Field.of("price").ascending())
        .limit(5)
        .raw_stage(
            "insert",
            options={
                "collection": Constant.of("featured_shoes"),
                "document_id": Field.of("__name__").document_id(),
            },
        )
        .execute()
    )
    # [END insert_advanced_queries]
    return results


def update_aggregation_subquery(db):
    from google.cloud.firestore_v1.pipeline_expressions import Constant, Field

    # [START update_aggregation_subquery]
    results = (
        db.pipeline()
        .collection("players")
        .where(
            Field.of("score").equal(
                db.pipeline()
                .collection("players")
                .aggregate(Field.of("score").maximum().as_("max_score"))
                .to_scalar_expression()
            )
        )
        .update(Constant.of(True).as_("is_top_scorer"))
        .execute()
    )
    # [END update_aggregation_subquery]
    return results


def upsert_migrate_users(db):
    from google.cloud.firestore_v1.pipeline_expressions import Constant, Field

    # [START upsert_migrate_users]
    results = (
        db.pipeline()
        .collection("legacy_users")
        .raw_stage(
            "upsert",
            options={
                "collection": Constant.of("users"),
                "document_id": Field.of("__name__").document_id(),
            },
        )
        .execute()
    )
    # [END upsert_migrate_users]
    return results


def upsert_in_place(db):
    from google.cloud.firestore_v1.pipeline_expressions import Constant, Field

    # [START upsert_in_place]
    results = (
        db.pipeline()
        .collection("cities")
        .where(Field.of("name").equal("San Francisco"))
        .raw_stage("upsert", Constant.of(880000).as_("population"))
        .execute()
    )
    # [END upsert_in_place]
    return results


def upsert_different_collection_explicit_id(db):
    from google.cloud.firestore_v1.pipeline_expressions import Constant

    # [START upsert_different_collection_explicit_id]
    results = (
        db.pipeline()
        .collection("source_coll")
        .add_fields(Constant.of(31).as_("age"))
        .raw_stage(
            "upsert",
            options={
                "collection": Constant.of("target_coll"),
                "document_id": Constant.of("new_doc_id"),
            },
        )
        .execute()
    )
    # [END upsert_different_collection_explicit_id]
    return results


def upsert_different_collection_existing_id(db):
    from google.cloud.firestore_v1.pipeline_expressions import Constant, Field

    # [START upsert_different_collection_existing_id]
    results = (
        db.pipeline()
        .collection("source_coll")
        .add_fields(Constant.of(31).as_("age"))
        .raw_stage(
            "upsert",
            options={
                "collection": Constant.of("target_coll"),
                "document_id": Field.of("__name__").document_id(),
            },
        )
        .execute()
    )
    # [END upsert_different_collection_existing_id]
    return results


def upsert_document_references(db):
    # [START upsert_document_references]
    results = (
        db.pipeline()
        .literals(
            {
                "__name__": db.collection("cities").document("SF"),
                "name": "San Francisco",
            }
        )
        .raw_stage("upsert")
        .execute()
    )
    # [END upsert_document_references]
    return results


def upsert_auto_generated_ids(db):
    from google.cloud.firestore_v1.pipeline_expressions import (
        Constant,
        FunctionExpression,
    )

    # [START upsert_auto_generated_ids]
    results = (
        db.pipeline()
        .literals({"name": "San Francisco"})
        .raw_stage(
            "upsert",
            options={
                "collection": Constant.of("cities"),
                "document_id": FunctionExpression("auto_id", []),
            },
        )
        .execute()
    )
    # [END upsert_auto_generated_ids]
    return results


def upsert_subcollection(db):
    from google.cloud.firestore_v1.pipeline_expressions import Constant, Field

    # [START upsert_subcollection]
    results = (
        db.pipeline()
        .literals({"title": "Buy groceries", "priority": "high"})
        .raw_stage(
            "upsert",
            options={
                "collection": Constant.of("users/user_a/tasks"),
                "document_id": Constant.of("task_").concat(
                    Field.of("priority")
                ),
            },
        )
        .execute()
    )
    # [END upsert_subcollection]
    return results


def upsert_advanced_queries(db):
    from google.cloud.firestore_v1.pipeline_expressions import Constant, Field

    # [START upsert_advanced_queries]
    results = (
        db.pipeline()
        .collection("products")
        .raw_stage("search", options={"query": Constant.of("shoes")})
        .sort(Field.of("price").ascending())
        .limit(5)
        .raw_stage(
            "upsert",
            options={
                "collection": Constant.of("featured_shoes"),
                "document_id": Field.of("__name__").document_id(),
            },
        )
        .execute()
    )
    # [END upsert_advanced_queries]
    return results


def upsert_aggregation_subquery(db):
    from google.cloud.firestore_v1.pipeline_expressions import Constant, Field

    # [START upsert_aggregation_subquery]
    results = (
        db.pipeline()
        .collection("players")
        .where(
            Field.of("score").equal(
                db.pipeline()
                .collection("players")
                .aggregate(Field.of("score").maximum().as_("max_score"))
                .to_scalar_expression()
            )
        )
        .add_fields(Constant.of(True).as_("is_top_scorer"))
        .raw_stage(
            "upsert",
            options={
                "collection": Constant.of("leaderboard"),
                "document_id": Field.of("__name__").document_id(),
            },
        )
        .execute()
    )
    # [END upsert_aggregation_subquery]
    return results


def rules_pipelines_filter_before(db):
    from google.cloud.firestore_v1.pipeline_expressions import Field

    # [START rules_pipelines_filter_before]
    results = (
        db.pipeline()
        .collection("SecretDocuments")
        .where(Field.of("userId").equal("abc"))
        .execute()
    )
    # [END rules_pipelines_filter_before]
    return results


def rules_pipelines_filter_after(db):
    from google.cloud.firestore_v1.pipeline_expressions import Field

    # [START rules_pipelines_filter_after]
    results = (
        db.pipeline()
        .collection("SecretDocuments")
        .limit(5)
        .where(Field.of("userId").equal("abc"))
        .execute()
    )
    # [END rules_pipelines_filter_after]
    return results
