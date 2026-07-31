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
            .where(Field.of("author").equal(Variable("owner_id")))
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
