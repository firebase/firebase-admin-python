# Firebase Admin Python SDK - Agent Guide

This document provides AI agents with a comprehensive guide to the conventions, design patterns, and architectural nuances of the Firebase Admin Python SDK. Adhering to this guide ensures that all contributions are idiomatic and align with the existing codebase.

## 1. High-Level Overview

The Firebase Admin Python SDK provides a Pythonic interface to Firebase services. Its design emphasizes thread-safety, a consistent and predictable API, and seamless integration with Google Cloud Platform services.

## 2. Directory Structure

-   `firebase_admin/`: The main package directory.
    -   `__init__.py`: The primary entry point. It exposes the `initialize_app()` function and manages the lifecycle of `App` instances.
    -   `exceptions.py`: Defines the custom exception hierarchy for the SDK.
    -   `_http_client.py`: Contains the centralized `JsonHttpClient` and `HttpxAsyncClient` for all outgoing HTTP requests.
    -   Service modules (e.g., `auth.py`, `db.py`, `messaging.py`): Each module contains the logic for a specific Firebase service.
-   `tests/`: Contains all unit tests.
    -   `tests/resources/`: Contains mock data, keys, and other test assets.
-   `integration/`: Contains all integration tests.* 
    -   These integration tests require a real Firebase project to run against.
    -   `integration/conftest.py`: Contains provides configurations for these integration tests including how credentials are provided through pytest.
-   `snippets/`: Contains code snippets used in documentation.
-   `setup.py`: Package definition, including the required environment dependencies.
-   `requirements.txt`: A list of all development dependencies.
-   `.pylintrc`: Configuration file for the `pylint` linter.
-   `CONTRIBUTING.md`: General guidelines for human contributors. Your instructions here supersede this file.

## 3. Core Design Patterns

### Initialization

The SDK is initialized by calling the `initialize_app(credential, options)` function. This creates a default `App` instance that SDK modules use implicitly. For multi-project use cases, named apps can be created by providing a `name` argument: `initialize_app(credential, options, name='my_app')`.

### Service Clients

Service clients are accessed via module-level factory functions. These functions automatically use the default app unless a specific `App` object is provided via the `app` parameter. The clients are created lazily and cached for the lifetime of the application.

- **Direct Action Modules (auth, db)**: Some modules provide functions that perform actions directly.
- **Client Factory Modules (firestore, storage)**: Other modules have a function (e.g., client() or bucket()) that returns a client object, which you then use for operations.


### Error Handling

-   All SDK-specific exceptions inherit from `firebase_admin.exceptions.FirebaseError`.
-   Specific error conditions are represented by subclasses, such as `firebase_admin.exceptions.InvalidArgumentError` and `firebase_admin.exceptions.UnauthenticatedError`.
-   Each service may additionaly define exceptions under these subclasses and apply them by passing a handle function to `_utils.handle_platform_error_from_requests()` or `_utils.handle_platform_error_from_httpx()`. Each services error handling patterns should be considered before making changes.

### HTTP Communication

-   All synchronous HTTP requests are made through the `JsonHttpClient` class in `firebase_admin._http_client`.
-   All asynchronous HTTP requests are made through the `HttpxAsyncClient` class in `firebase_admin._http_client`.
-   These clients handle authentication and retries for all API calls.

### Asynchronous Operations

Asynchronous operations are supported using Python's `asyncio` library. Asynchronous methods are typically named with an `_async` suffix (e.g., `messaging.send_each_async()`).

## 4. Coding Style and Naming Conventions

-   **Formatting:** This project uses **pylint** to enforce code style and detect potential errors. Before submitting code, you **must** run the linter and ensure your changes do not introduce any new errors. Run the linter from the repository's root directory with the following command:
    ```bash
    ./lint.sh all   # Lint all source files
    ```
    or 
    ```bash
    ./lint.sh   # Lint locally modified source files
    ```
-   **Naming:**
    -   Classes: `PascalCase` (e.g., `FirebaseError`).
    -   Methods and Functions: `snake_case` (e.g., `initialize_app`).
    -   Private Members: An underscore prefix (e.g., `_http_client`).
    -   Constants: `UPPER_SNAKE_CASE` (e.g., `INVALID_ARGUMENT`).

## 5. Testing Philosophy

-   **Unit Tests:**
    -   Located in the `tests/` directory.
    -   Test files follow the `test_*.py` naming convention.
    -   Unit tests can be run using the following command:
        ```bash
        pytest
        ```
-   **Integration Tests:**
    -   Located in the `integration/` directory.
    -   These tests make real API calls to Firebase services and require a configured project. Running these tests be should be ignored without a project and instead rely on the repository's GitHub Actions.

## 6. Dependency Management

-   **Manager:** `pip`
-   **Manifest:** `requirements.txt`
-   **Command:** `pip install -r requirements.txt`

## 7. Critical Developer Journeys

### Journey 1: How to Add a New API Method

1.  **Define Public Method:** Add the new method or change to the appropriate service client files (e.g., `firebase_admin/auth.py`).
2.  **Expose the public API method** by updating the `__all__` constant with the name of the new method. 
3.  **Internal Logic:** Implement the core logic within the service package.
4.  **HTTP Client:** Use the HTTP client (`JsonHttpClient` or `HttpxAsyncClient`) to make the API call.
5.  **Error Handling:** Catching exceptions from the HTTP client and raise the appropriate `FirebaseError` subclass using the services error handling logic
6.  **Testing:**
    -   Add unit tests in the corresponding `test_*.py` file (e.g., `tests/test_user_mgt.py`).
    -   Add integration tests in the `integration/` directory if applicable.
7.  **Snippets:** (Optional) Add or update code snippets in the `snippets/` directory.

### Journey 2: How to Deprecate a Field/Method in an Existing API

1.  **Add Deprecation Note:** Locate where the deprecated object is defined and add a deprecation note to its docstring (e.g. `X is deprecated. Use Y instead.`).
2.  **Add Deprecation Warning:** In the same location where the deprecated object is defined, add a deprecation warning to the code. (e.g. `warnings.warn('X is deprecated. Use Y instead.', DeprecationWarning)`)

## 8. Critical Do's and Don'ts

-   **DO:** Use the centralized `JsonHttpClient` or `HttpxAsyncClient` for all HTTP requests.
-   **DO:** Follow the established error handling patterns by using `FirebaseError` and its subclasses.
-   **DON'T:** Expose implementation details from private (underscored) modules or functions in the public API.
-   **DON'T:** Introduce new third-party dependencies without updating `requirements.txt` and `setup.py`.

## 9. Branch Creation
- When creating a new barnch use the format `agentName-short-description`.
    * Example: `jules-auth-token-parsing`
    * Example: `gemini-add-storage-file-signer`

## 10. Commit and Pull Request Generation

After implementing and testing a change, you may create a commit and pull request which must follow the following these rules:

### Commit and Pull Request Title Format:
Use the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification: `type(scope): subject`
- `type` should be one of `feat`, `fix` or `chore`.
- `scope` should be the service package changed (e.g., `auth`, `rtdb`, `deps`).
    - **Note**: Some services use specific abbreviations. Use the abbreviation if one exists. Common abbreviations include:
        - `messaging` -> `fcm`
        - `dataconnect` -> `fdc`
        - `database` -> `rtdb`
        - `appcheck` -> `fac`
- `subject` should be a brief summary of the change depending on the action:
    - For pull requests this should focus on the larger goal the included commits achieve.
        - Example: `fix(auth): Resolved issue with custom token verification`
    - For commits this should focus on the specific changes made in that commit.
        - Example: `fix(auth): Added a new token verification check`

### Commit Body:
This should be a brief explanation of code changes.

Example:
```
feat(fcm): Added `send_each_for_multicast` support for multicast messages

Added a new `send_each_for_multicast` method to the messaging client. This method wraps the `send_each` method and sends the same message to each token.
```

### Pull Request Body:
- A brief explanation of the problem and the solution.
- A summary of the testing strategy (e.g., "Added a new unit test to verify the fix.").
- A **Context Sources** section that lists the `id` and repository path of every `AGENTS.md` file you used.

Example:
```
feat(fcm): Added support for multicast messages

This change introduces a new `send_each_for_multicast` method to the messaging client, allowing developers to send a single message to multiple tokens efficiently.

Testing: Added unit tests in `tests/test_messaging.py` with mock requests and an integration test in `integration/test_messaging.py`.

Context Sources Used:
- id: firebase-admin-python
```

## 11. Metadata
- id: firebase-admin-python