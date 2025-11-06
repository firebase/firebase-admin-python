# Copyright 2025 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from google.cloud.firestore import Query
from google.cloud.firestore_v1.pipeline import Pipeline
from google.cloud.firestore_v1.pipeline_source import PipelineSource
from google.cloud.firestore_v1.pipeline_expressions import (
    AggregateFunction,
    Constant,
    Expression,
    Field,
    Count,
)
from google.cloud.firestore_v1.pipeline_expressions import (
    And,
    Conditional,
    Or,
    Not,
    Xor,
)
from google.cloud.firestore_v1.pipeline_stages import (
    Aggregate,
    FindNearestOptions,
    SampleOptions,
    UnnestOptions,
)
from google.cloud.firestore_v1.base_vector_query import DistanceMeasure
from google.cloud.firestore_v1.vector import Vector
from google.cloud.firestore_v1.client import Client

import firebase_admin
from firebase_admin import firestore

default_app = firebase_admin.initialize_app()
client = firestore.client(default_app, "your-new-enterprise-database")


# pylint: disable=invalid-name
def pipeline_concepts():
    # [START pipeline_concepts]
    pipeline = (
        client.pipeline()
        .collection("cities")
        .where(Field.of("population").greater_than(100_000))
        .sort(Field.of("name").ascending())
        .limit(10)
    )
    # [END pipeline_concepts]
    print(pipeline)


def basic_read():
    # [START basic_read]
    pipeline = client.pipeline().collection("users")
    for result in pipeline.execute():
        print(f"{result.id} => {result.data()}")
    # or, asynchronously
    result_stream = pipeline.stream()
    async for result in result_stream:
        print(f"{result.id} => {result.data()}")
    # [END basic_read]


def pipeline_initialization():
    # [START pipeline_initialization]
    firestore_client = firestore.client(default_app, "your-new-enterprise-database")
    pipeline = firestore_client.pipeline()
    # [END pipeline_initialization]
    print(pipeline)


def field_vs_constants():
    # [START field_or_constant]
    pipeline = (
        client.pipeline()
        .collection("cities")
        .where(Field.of("name").equal(Constant.of("Toronto")))
    )
    # [END field_or_constant]
    print(pipeline)


def input_stages():
    # [START input_stages]
    # Return all restaurants in San Francisco
    results = client.pipeline().collection("cities/sf/restaurants").execute()

    # Return all restaurants
    results = client.pipeline().collection_group("restaurants").execute()

    # Return all documents across all collections in the database (the entire database)
    results = client.pipeline().database().execute()

    # Batch read of 3 documents
    results = (
        client.pipeline()
        .documents(
            client.collection("cities").document("SF"),
            client.collection("cities").document("DC"),
            client.collection("cities").document("NY"),
        )
        .execute()
    )
    # [END input_stages]
    for result in results:
        print(result)


def where_pipeline():
    # [START pipeline_where]
    from google.cloud.firestore_v1.pipeline_expressions import And, Field

    results = (
        client.pipeline()
        .collection("books")
        .where(Field.of("rating").equal(5))
        .where(Field.of("published").less_than(1900))
        .execute()
    )

    results = (
        client.pipeline()
        .collection("books")
        .where(And(Field.of("rating").equal(5), Field.of("published").less_than(1900)))
        .execute()
    )
    # [END pipeline_where]
    for result in results:
        print(result)


def aggregate_groups():
    # [START aggregate_groups]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    results = (
        client.pipeline()
        .collection("books")
        .aggregate(
            Field.of("rating").average().as_("avg_rating"), groups=[Field.of("genre")]
        )
        .execute()
    )
    # [END aggregate_groups]
    for result in results:
        print(result)


def aggregate_distinct():
    # [START aggregate_distinct]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    results = (
        client.pipeline()
        .collection("books")
        .distinct(Field.of("author").to_upper().as_("author"), "genre")
        .execute()
    )
    # [END aggregate_distinct]
    for result in results:
        print(result)


def sort():
    # [START sort]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    results = (
        client.pipeline()
        .collection("books")
        .sort(Field.of("release_date").descending(), Field.of("author").ascending())
        .execute()
    )
    # [END sort]
    for result in results:
        print(result)


def sort_comparison():
    # [START sort_comparison]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    query = (
        client.collection("cities")
        .order_by("state")
        .order_by("population", direction=Query.DESCENDING)
    )

    pipeline = (
        client.pipeline()
        .collection("books")
        .sort(Field.of("release_date").descending(), Field.of("author").ascending())
    )
    # [END sort_comparison]
    print(query)
    print(pipeline)


def functions_example():
    # [START functions_example]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    # Type 1: Scalar (for use in non-aggregation stages)
    # Example: Return the min store price for each book.
    results = (
        client.pipeline()
        .collection("books")
        .select(
            Field.of("current").logical_minimum(Field.of("updated")).as_("price_min")
        )
        .execute()
    )

    # Type 2: Aggregation (for use in aggregate stages)
    # Example: Return the min price of all books.
    results = (
        client.pipeline()
        .collection("books")
        .aggregate(Field.of("price").minimum().as_("min_price"))
        .execute()
    )
    # [END functions_example]
    for result in results:
        print(result)


def creating_indexes():
    # [START query_example]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    results = (
        client.pipeline()
        .collection("books")
        .where(Field.of("published").less_than(1900))
        .where(Field.of("genre").equal("Science Fiction"))
        .where(Field.of("rating").greater_than(4.3))
        .sort(Field.of("published").descending())
        .execute()
    )
    # [END query_example]
    for result in results:
        print(result)


def sparse_indexes():
    # [START sparse_index_example]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    results = (
        client.pipeline()
        .collection("books")
        .where(Field.of("category").like("%fantasy%"))
        .execute()
    )
    # [END sparse_index_example]
    for result in results:
        print(result)


def sparse_indexes2():
    # [START sparse_index_example_2]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    results = (
        client.pipeline()
        .collection("books")
        .sort(Field.of("release_date").ascending())
        .execute()
    )
    # [END sparse_index_example_2]
    for result in results:
        print(result)


def covered_query():
    # [START covered_query]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    results = (
        client.pipeline()
        .collection("books")
        .where(Field.of("category").like("%fantasy%"))
        .where(Field.of("title").exists())
        .where(Field.of("author").exists())
        .select("title", "author")
        .execute()
    )
    # [END covered_query]
    for result in results:
        print(result)


def pagination():
    # [START pagination_not_supported_preview]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    # Existing pagination via `start_at()`
    query = (
        client.collection("cities")
        .order_by("population")
        .start_at({"population": 1_000_000})
    )

    # Private preview workaround using pipelines
    pipeline = (
        client.pipeline()
        .collection("cities")
        .where(Field.of("population").greater_than_or_equal(1_000_000))
        .sort(Field.of("population").descending())
    )
    # [END pagination_not_supported_preview]
    print(query)
    print(pipeline)


def collection_stage():
    # [START collection_example]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    results = (
        client.pipeline()
        .collection("users/bob/games")
        .sort(Field.of("name").ascending())
        .execute()
    )
    # [END collection_example]
    for result in results:
        print(result)


def collection_group_stage():
    # [START collection_group_example]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    results = (
        client.pipeline()
        .collection_group("games")
        .sort(Field.of("name").ascending())
        .execute()
    )
    # [END collection_group_example]
    for result in results:
        print(result)


def database_stage():
    # [START database_example]
    from google.cloud.firestore_v1.pipeline_expressions import Count

    # Count all documents in the database
    results = client.pipeline().database().aggregate(Count().as_("total")).execute()
    # [END database_example]
    for result in results:
        print(result)


def documents_stage():
    # [START documents_example]
    results = (
        client.pipeline()
        .documents(
            client.collection("cities").document("SF"),
            client.collection("cities").document("DC"),
            client.collection("cities").document("NY"),
        )
        .execute()
    )
    # [END documents_example]
    for result in results:
        print(result)


def replace_with_stage():
    # [START initial_data]
    client.collection("cities").document("SF").set(
        {
            "name": "San Francisco",
            "population": 800_000,
            "location": {"country": "USA", "state": "California"},
        }
    )
    client.collection("cities").document("TO").set(
        {
            "name": "Toronto",
            "population": 3_000_000,
            "province": "ON",
            "location": {"country": "Canada", "province": "Ontario"},
        }
    )
    client.collection("cities").document("NY").set(
        {
            "name": "New York",
            "population": 8_500_000,
            "location": {"country": "USA", "state": "New York"},
        }
    )
    client.collection("cities").document("AT").set(
        {
            "name": "Atlantis",
        }
    )
    # [END initial_data]

    # [START full_replace]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    names = (
        client.pipeline()
        .collection("cities")
        .replace_with(Field.of("location"))
        .execute()
    )
    # [END full_replace]

    # [START map_merge_overwrite]
    # unsupported in client SDKs for now
    # [END map_merge_overwrite]
    for name in names:
        print(name)


def sample_stage():
    # [START sample_example]
    # Get a sample of 100 documents in a database
    results = client.pipeline().database().sample(100).execute()

    # Randomly shuffle a list of 3 documents
    results = (
        client.pipeline()
        .documents(
            client.collection("cities").document("SF"),
            client.collection("cities").document("NY"),
            client.collection("cities").document("DC"),
        )
        .sample(3)
        .execute()
    )
    # [END sample_example]
    for result in results:
        print(result)


def sample_percent():
    # [START sample_percent]
    from google.cloud.firestore_v1.pipeline_stages import SampleOptions

    # Get a sample of on average 50% of the documents in the database
    results = (
        client.pipeline().database().sample(SampleOptions.percentage(0.5)).execute()
    )
    # [END sample_percent]
    for result in results:
        print(result)


def union_stage():
    # [START union_stage]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    results = (
        client.pipeline()
        .collection("cities/SF/restaurants")
        .where(Field.of("type").equal("Chinese"))
        .union(
            client.pipeline()
            .collection("cities/NY/restaurants")
            .where(Field.of("type").equal("Italian"))
        )
        .where(Field.of("rating").greater_than_or_equal(4.5))
        .sort(Field.of("__name__").descending())
        .execute()
    )
    # [END union_stage]
    for result in results:
        print(result)


def union_stage_stable():
    # [START union_stage_stable]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    results = (
        client.pipeline()
        .collection("cities/SF/restaurants")
        .where(Field.of("type").equal("Chinese"))
        .union(
            client.pipeline()
            .collection("cities/NY/restaurants")
            .where(Field.of("type").equal("Italian"))
        )
        .where(Field.of("rating").greater_than_or_equal(4.5))
        .sort(Field.of("__name__").descending())
        .execute()
    )
    # [END union_stage_stable]
    for result in results:
        print(result)


def unnest_stage():
    # [START unnest_stage]
    from google.cloud.firestore_v1.pipeline_expressions import Field
    from google.cloud.firestore_v1.pipeline_stages import UnnestOptions

    results = (
        client.pipeline()
        .database()
        .unnest(
            Field.of("arrayField").as_("unnestedArrayField"),
            options=UnnestOptions(index_field="index"),
        )
        .execute()
    )
    # [END unnest_stage]
    for result in results:
        print(result)


def unnest_stage_empty_or_non_array():
    # [START unnest_edge_cases]
    from google.cloud.firestore_v1.pipeline_expressions import Field
    from google.cloud.firestore_v1.pipeline_stages import UnnestOptions

    # Input
    # { "identifier" : 1, "neighbors": [ "Alice", "Cathy" ] }
    # { "identifier" : 2, "neighbors": []                   }
    # { "identifier" : 3, "neighbors": "Bob"                }

    results = (
        client.pipeline()
        .database()
        .unnest(
            Field.of("neighbors").as_("unnestedNeighbors"),
            options=UnnestOptions(index_field="index"),
        )
        .execute()
    )

    # Output
    # { "identifier": 1, "neighbors": [ "Alice", "Cathy" ],
    #   "unnestedNeighbors": "Alice", "index": 0 }
    # { "identifier": 1, "neighbors": [ "Alice", "Cathy" ],
    #   "unnestedNeighbors": "Cathy", "index": 1 }
    # { "identifier": 3, "neighbors": "Bob", "index": null}
    # [END unnest_edge_cases]
    for result in results:
        print(result)


def count_function():
    # [START count_function]
    from google.cloud.firestore_v1.pipeline_expressions import Count

    # Total number of books in the collection
    count_all = (
        client.pipeline().collection("books").aggregate(Count().as_("count")).execute()
    )

    # Number of books with nonnull `ratings` field
    count_field = (
        client.pipeline()
        .collection("books")
        .aggregate(Count("ratings").as_("count"))
        .execute()
    )
    # [END count_function]
    for result in count_all:
        print(result)
    for result in count_field:
        print(result)


def count_if_function():
    # [START count_if]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .aggregate(Field.of("rating").greater_than(4).count_if().as_("filteredCount"))
        .execute()
    )
    # [END count_if]
    for res in result:
        print(res)


def count_distinct_function():
    # [START count_distinct]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .aggregate(Field.of("author").count_distinct().as_("unique_authors"))
        .execute()
    )
    # [END count_distinct]
    for res in result:
        print(res)


def sum_function():
    # [START sum_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("cities")
        .aggregate(Field.of("population").sum().as_("totalPopulation"))
        .execute()
    )
    # [END sum_function]
    for res in result:
        print(res)


def avg_function():
    # [START avg_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("cities")
        .aggregate(Field.of("population").average().as_("averagePopulation"))
        .execute()
    )
    # [END avg_function]
    for res in result:
        print(res)


def min_function():
    # [START min_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .aggregate(Field.of("price").minimum().as_("minimumPrice"))
        .execute()
    )
    # [END min_function]
    for res in result:
        print(res)


def max_function():
    # [START max_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .aggregate(Field.of("price").maximum().as_("maximumPrice"))
        .execute()
    )
    # [END max_function]
    for res in result:
        print(res)


def add_function():
    # [START add_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("soldBooks").add(Field.of("unsoldBooks")).as_("totalBooks"))
        .execute()
    )
    # [END add_function]
    for res in result:
        print(res)


def subtract_function():
    # [START subtract_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    store_credit = 7
    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("price").subtract(store_credit).as_("totalCost"))
        .execute()
    )
    # [END subtract_function]
    for res in result:
        print(res)


def multiply_function():
    # [START multiply_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("price").multiply(Field.of("soldBooks")).as_("revenue"))
        .execute()
    )
    # [END multiply_function]
    for res in result:
        print(res)


def divide_function():
    # [START divide_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("ratings").divide(Field.of("soldBooks")).as_("reviewRate"))
        .execute()
    )
    # [END divide_function]
    for res in result:
        print(res)


def mod_function():
    # [START mod_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    display_capacity = 1000
    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("unsoldBooks").mod(display_capacity).as_("warehousedBooks"))
        .execute()
    )
    # [END mod_function]
    for res in result:
        print(res)


def ceil_function():
    # [START ceil_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    books_per_shelf = 100
    result = (
        client.pipeline()
        .collection("books")
        .select(
            Field.of("unsoldBooks")
            .divide(books_per_shelf)
            .ceil()
            .as_("requiredShelves")
        )
        .execute()
    )
    # [END ceil_function]
    for res in result:
        print(res)


def floor_function():
    # [START floor_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .add_fields(
            Field.of("wordCount").divide(Field.of("pages")).floor().as_("wordsPerPage")
        )
        .execute()
    )
    # [END floor_function]
    for res in result:
        print(res)


def round_function():
    # [START round_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(
            Field.of("soldBooks")
            .multiply(Field.of("price"))
            .round()
            .as_("partialRevenue")
        )
        .aggregate(Field.of("partialRevenue").sum().as_("totalRevenue"))
        .execute()
    )
    # [END round_function]
    for res in result:
        print(res)


def pow_function():
    # [START pow_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    googleplexLat = 37.4221
    googleplexLng = -122.0853
    result = (
        client.pipeline()
        .collection("cities")
        .add_fields(
            Field.of("lat")
            .subtract(googleplexLat)
            .multiply(111)  # km per degree
            .pow(2)
            .as_("latitudeDifference"),
            Field.of("lng")
            .subtract(googleplexLng)
            .multiply(111)  # km per degree
            .pow(2)
            .as_("longitudeDifference"),
        )
        .select(
            Field.of("latitudeDifference")
            .add(Field.of("longitudeDifference"))
            .sqrt()
            # Inaccurate for large distances or close to poles
            .as_("approximateDistanceToGoogle")
        )
        .execute()
    )
    # [END pow_function]
    for res in result:
        print(res)


def sqrt_function():
    # [START sqrt_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    googleplexLat = 37.4221
    googleplexLng = -122.0853
    result = (
        client.pipeline()
        .collection("cities")
        .add_fields(
            Field.of("lat")
            .subtract(googleplexLat)
            .multiply(111)  # km per degree
            .pow(2)
            .as_("latitudeDifference"),
            Field.of("lng")
            .subtract(googleplexLng)
            .multiply(111)  # km per degree
            .pow(2)
            .as_("longitudeDifference"),
        )
        .select(
            Field.of("latitudeDifference")
            .add(Field.of("longitudeDifference"))
            .sqrt()
            # Inaccurate for large distances or close to poles
            .as_("approximateDistanceToGoogle")
        )
        .execute()
    )
    # [END sqrt_function]
    for res in result:
        print(res)


def exp_function():
    # [START exp_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("rating").exp().as_("expRating"))
        .execute()
    )
    # [END exp_function]
    for res in result:
        print(res)


def ln_function():
    # [START ln_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("rating").ln().as_("lnRating"))
        .execute()
    )
    # [END ln_function]
    for res in result:
        print(res)


def log_function():
    # [START log_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("rating").log(2).as_("log2Rating"))
        .execute()
    )
    # [END log_function]
    for res in result:
        print(res)


def array_concat():
    # [START array_concat]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("genre").array_concat(Field.of("subGenre")).as_("allGenres"))
        .execute()
    )
    # [END array_concat]
    for res in result:
        print(res)


def array_contains():
    # [START array_contains]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("genre").array_contains("mystery").as_("isMystery"))
        .execute()
    )
    # [END array_contains]
    for res in result:
        print(res)


def array_contains_all():
    # [START array_contains_all]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(
            Field.of("genre")
            .array_contains_all(["fantasy", "adventure"])
            .as_("isFantasyAdventure")
        )
        .execute()
    )
    # [END array_contains_all]
    for res in result:
        print(res)


def array_contains_any():
    # [START array_contains_any]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(
            Field.of("genre")
            .array_contains_any(["fantasy", "nonfiction"])
            .as_("isMysteryOrFantasy")
        )
        .execute()
    )
    # [END array_contains_any]
    for res in result:
        print(res)


def array_length():
    # [START array_length]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("genre").array_length().as_("genreCount"))
        .execute()
    )
    # [END array_length]
    for res in result:
        print(res)


def array_reverse():
    # [START array_reverse]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("genre").array_reverse().as_("reversedGenres"))
        .execute()
    )
    # [END array_reverse]
    for res in result:
        print(res)


def equal_function():
    # [START equal_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("rating").equal(5).as_("hasPerfectRating"))
        .execute()
    )
    # [END equal_function]
    for res in result:
        print(res)


def greater_than_function():
    # [START greater_than]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("rating").greater_than(4).as_("hasHighRating"))
        .execute()
    )
    # [END greater_than]
    for res in result:
        print(res)


def greater_than_or_equal_to_function():
    # [START greater_or_equal]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(
            Field.of("published")
            .greater_than_or_equal(1900)
            .as_("publishedIn20thCentury")
        )
        .execute()
    )
    # [END greater_or_equal]
    for res in result:
        print(res)


def less_than_function():
    # [START less_than]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("published").less_than(1923).as_("isPublicDomainProbably"))
        .execute()
    )
    # [END less_than]
    for res in result:
        print(res)


def less_than_or_equal_to_function():
    # [START less_or_equal]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("rating").less_than_or_equal(2).as_("hasBadRating"))
        .execute()
    )
    # [END less_or_equal]
    for res in result:
        print(res)


def not_equal_function():
    # [START not_equal]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("title").not_equal("1984").as_("not1984"))
        .execute()
    )
    # [END not_equal]
    for res in result:
        print(res)


def exists_function():
    # [START exists_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("rating").exists().as_("hasRating"))
        .execute()
    )
    # [END exists_function]
    for res in result:
        print(res)


def and_function():
    # [START and_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field, And

    result = (
        client.pipeline()
        .collection("books")
        .select(
            And(
                Field.of("rating").greater_than(4), Field.of("price").less_than(10)
            ).as_("under10Recommendation")
        )
        .execute()
    )
    # [END and_function]
    for res in result:
        print(res)


def or_function():
    # [START or_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field, And

    result = (
        client.pipeline()
        .collection("books")
        .select(
            Or(
                Field.of("genre").equal("Fantasy"),
                Field.of("tags").array_contains("adventure"),
            ).as_("matchesSearchFilters")
        )
        .execute()
    )
    # [END or_function]
    for res in result:
        print(res)


def xor_function():
    # [START xor_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field, Xor

    result = (
        client.pipeline()
        .collection("books")
        .select(
            Xor(
                [
                    Field.of("tags").array_contains("magic"),
                    Field.of("tags").array_contains("nonfiction"),
                ]
            ).as_("matchesSearchFilters")
        )
        .execute()
    )
    # [END xor_function]
    for res in result:
        print(res)


def not_function():
    # [START not_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field, Not

    result = (
        client.pipeline()
        .collection("books")
        .select(Not(Field.of("tags").array_contains("nonfiction")).as_("isFiction"))
        .execute()
    )
    # [END not_function]
    for res in result:
        print(res)


def cond_function():
    # [START cond_function]
    from google.cloud.firestore_v1.pipeline_expressions import (
        Field,
        Constant,
        Conditional,
    )

    result = (
        client.pipeline()
        .collection("books")
        .select(
            Field.of("tags")
            .array_concat(
                Conditional(
                    Field.of("pages").greater_than(100),
                    Constant.of("longRead"),
                    Constant.of("shortRead"),
                )
            )
            .as_("extendedTags")
        )
        .execute()
    )
    # [END cond_function]
    for res in result:
        print(res)


def equal_any_function():
    # [START eq_any]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(
            Field.of("genre")
            .equal_any(["Science Fiction", "Psychological Thriller"])
            .as_("matchesGenreFilters")
        )
        .execute()
    )
    # [END eq_any]
    for res in result:
        print(res)


def not_equal_any_function():
    # [START not_eq_any]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(
            Field.of("author")
            .not_equal_any(["George Orwell", "F. Scott Fitzgerald"])
            .as_("byExcludedAuthors")
        )
        .execute()
    )
    # [END not_eq_any]
    for res in result:
        print(res)


def max_logical_function():
    # [START max_logical_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("rating").logical_maximum(1).as_("flooredRating"))
        .execute()
    )
    # [END max_logical_function]
    for res in result:
        print(res)


def min_logical_function():
    # [START min_logical_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("rating").logical_minimum(5).as_("cappedRating"))
        .execute()
    )
    # [END min_logical_function]
    for res in result:
        print(res)


def map_get_function():
    # [START map_get]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("awards").map_get("pulitzer").as_("hasPulitzerAward"))
        .execute()
    )
    # [END map_get]
    for res in result:
        print(res)


def byte_length_function():
    # [START byte_length]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("title").byte_length().as_("titleByteLength"))
        .execute()
    )
    # [END byte_length]
    for res in result:
        print(res)


def char_length_function():
    # [START char_length]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("title").char_length().as_("titleCharLength"))
        .execute()
    )
    # [END char_length]
    for res in result:
        print(res)


def starts_with_function():
    # [START starts_with]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(
            Field.of("title").starts_with("The").as_("needsSpecialAlphabeticalSort")
        )
        .execute()
    )
    # [END starts_with]
    for res in result:
        print(res)


def ends_with_function():
    # [START ends_with]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("inventory/devices/laptops")
        .select(Field.of("name").ends_with("16 inch").as_("16InLaptops"))
        .execute()
    )
    # [END ends_with]
    for res in result:
        print(res)


def like_function():
    # [START like]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("genre").like("%Fiction").as_("anyFiction"))
        .execute()
    )
    # [END like]
    for res in result:
        print(res)


def regex_contains_function():
    # [START regex_contains]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("documents")
        .select(
            Field.of("title")
            .regex_contains("Firestore (Enterprise|Standard)")
            .as_("isFirestoreRelated")
        )
        .execute()
    )
    # [END regex_contains]
    for res in result:
        print(res)


def regex_match_function():
    # [START regex_match]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("documents")
        .select(
            Field.of("title")
            .regex_match("Firestore (Enterprise|Standard)")
            .as_("isFirestoreExactly")
        )
        .execute()
    )
    # [END regex_match]
    for res in result:
        print(res)


def str_concat_function():
    # [START str_concat]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(
            Field.of("title")
            .concat(" by ", Field.of("author"))
            .as_("fullyQualifiedTitle")
        )
        .execute()
    )
    # [END str_concat]
    for res in result:
        print(res)


def str_contains_function():
    # [START string_contains]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("articles")
        .select(Field.of("body").string_contains("Firestore").as_("isFirestoreRelated"))
        .execute()
    )
    # [END string_contains]
    for res in result:
        print(res)


def to_upper_function():
    # [START to_upper]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("authors")
        .select(Field.of("name").to_upper().as_("uppercaseName"))
        .execute()
    )
    # [END to_upper]
    for res in result:
        print(res)


def to_lower_function():
    # [START to_lower]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("authors")
        .select(Field.of("genre").to_lower().equal("fantasy").as_("isFantasy"))
        .execute()
    )
    # [END to_lower]
    for res in result:
        print(res)


def substr_function():
    # [START substr_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .where(Field.of("title").starts_with("The "))
        .select(Field.of("title").substring(4).as_("titleWithoutLeadingThe"))
        .execute()
    )
    # [END substr_function]
    for res in result:
        print(res)


def str_reverse_function():
    # [START str_reverse]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("name").string_reverse().as_("reversedName"))
        .execute()
    )
    # [END str_reverse]
    for res in result:
        print(res)


def str_trim_function():
    # [START trim_function]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("name").trim().as_("whitespaceTrimmedName"))
        .execute()
    )
    # [END trim_function]
    for res in result:
        print(res)


def str_replace_function():
    # not yet supported until GA
    pass


def str_split_function():
    # not yet supported until GA
    pass


def unix_micros_to_timestamp_function():
    # [START unix_micros_timestamp]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("documents")
        .select(
            Field.of("createdAtMicros")
            .unix_micros_to_timestamp()
            .as_("createdAtString")
        )
        .execute()
    )
    # [END unix_micros_timestamp]
    for res in result:
        print(res)


def unix_millis_to_timestamp_function():
    # [START unix_millis_timestamp]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("documents")
        .select(
            Field.of("createdAtMillis")
            .unix_millis_to_timestamp()
            .as_("createdAtString")
        )
        .execute()
    )
    # [END unix_millis_timestamp]
    for res in result:
        print(res)


def unix_seconds_to_timestamp_function():
    # [START unix_seconds_timestamp]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("documents")
        .select(
            Field.of("createdAtSeconds")
            .unix_seconds_to_timestamp()
            .as_("createdAtString")
        )
        .execute()
    )
    # [END unix_seconds_timestamp]
    for res in result:
        print(res)


def timestamp_add_function():
    # [START timestamp_add]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("documents")
        .select(Field.of("createdAt").timestamp_add("day", 3653).as_("expiresAt"))
        .execute()
    )
    # [END timestamp_add]
    for res in result:
        print(res)


def timestamp_sub_function():
    # [START timestamp_sub]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("documents")
        .select(
            Field.of("expiresAt")
            .timestamp_subtract("day", 14)
            .as_("sendWarningTimestamp")
        )
        .execute()
    )
    # [END timestamp_sub]
    for res in result:
        print(res)


def timestamp_to_unix_micros_function():
    # [START timestamp_unix_micros]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("documents")
        .select(Field.of("dateString").timestamp_to_unix_micros().as_("unixMicros"))
        .execute()
    )
    # [END timestamp_unix_micros]
    for res in result:
        print(res)


def timestamp_to_unix_millis_function():
    # [START timestamp_unix_millis]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("documents")
        .select(Field.of("dateString").timestamp_to_unix_millis().as_("unixMillis"))
        .execute()
    )
    # [END timestamp_unix_millis]
    for res in result:
        print(res)


def timestamp_to_unix_seconds_function():
    # [START timestamp_unix_seconds]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("documents")
        .select(Field.of("dateString").timestamp_to_unix_seconds().as_("unixSeconds"))
        .execute()
    )
    # [END timestamp_unix_seconds]
    for res in result:
        print(res)


def cosine_distance_function():
    # [START cosine_distance]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    sample_vector = Vector([0.0, 1.0, 2.0, 3.0, 4.0, 5.0])
    result = (
        client.pipeline()
        .collection("books")
        .select(
            Field.of("embedding").cosine_distance(sample_vector).as_("cosineDistance")
        )
        .execute()
    )
    # [END cosine_distance]
    for res in result:
        print(res)


def dot_product_function():
    # [START dot_product]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    sample_vector = Vector([0.0, 1.0, 2.0, 3.0, 4.0, 5.0])
    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("embedding").dot_product(sample_vector).as_("dotProduct"))
        .execute()
    )
    # [END dot_product]
    for res in result:
        print(res)


def euclidean_distance_function():
    # [START euclidean_distance]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    sample_vector = Vector([0.0, 1.0, 2.0, 3.0, 4.0, 5.0])
    result = (
        client.pipeline()
        .collection("books")
        .select(
            Field.of("embedding")
            .euclidean_distance(sample_vector)
            .as_("euclideanDistance")
        )
        .execute()
    )
    # [END euclidean_distance]
    for res in result:
        print(res)


def vector_length_function():
    # [START vector_length]
    from google.cloud.firestore_v1.pipeline_expressions import Field

    result = (
        client.pipeline()
        .collection("books")
        .select(Field.of("embedding").vector_length().as_("vectorLength"))
        .execute()
    )
    # [END vector_length]
    for res in result:
        print(res)
