---
id: firebase-admin-python
scope: "/"
description: "Base AI agent development and contribution rules for the entire repository."
---

# AI Agent Development Context for firebase-admin-python

This document provides the technical context necessary to develop and contribute code to the `firebase-admin-python` repository. It outlines the architecture, development workflow, coding conventions, and the official contribution process.

---

## 1. Repository Overview & Architecture

* **Project Goal**: This SDK provides Python developers with server-side (backend) access to Firebase services. It enables administrative tasks from privileged environments to perform actions like:
    * Perform queries and mutations on a Firebase Data Connect service for bulk data management and other operations with full admin privileges.
    * Read and write Realtime Database data with full admin privileges.
    * Programmatically send Firebase Cloud Messaging messages using a simple, alternative approach to the Firebase Cloud Messaging server protocols.
    * Generate and verify Firebase auth tokens.
    * Access Google Cloud resources like Cloud Storage buckets and Cloud Firestore databases associated with your Firebase projects.
    * Create your own simplified admin console to do things like look up user data or change a user's email address for authentication.
* **Core Technology**: The SDK is a wrapper around lower-level Google Cloud and Firebase REST APIs. It handles authentication, credential management, and provides a more convenient, Pythonic interface.
* **Supported Python Versions**: Python 3.9+. Code contributions must be compatible with this range.

### Key Directory Structure

* `firebase_admin/`: Main package source code.
    * `__init__.py`: Defines the central `App` object and `initialize_app()` logic. This is the entry point.
    * `credentials.py`: Handles OAuth2 credential fetching.
    * `auth.py`, `firestore.py`, `messaging.py`, etc.: Each file represents a public Firebase service module. This is where most feature work will occur.
    * `exceptions.py`: Contains all custom firebase admin exception classes for the SDK.
    * `_utils.py`: Contains common helper functions and modules.
* `tests/`: All unit tests.
    * The structure of `tests/` mirrors the `firebase_admin/` source directory.
    * `tests/resources/`: Contains mock data, keys, and other test assets.
* `integration/`: All integration tests.
    * These integration tests require a real Firebase project to run against.
    * `integration/conftest.py`: Contains provides configurations for these integration tests including how credentials are provided through pytest.
* `setup.py`: Package definition, including the reuired user dependencies.
* `requirements.txt`: A list of all development dependencies.
* `.pylintrc`: Configuration file for the `pylint` linter.
* `CONTRIBUTING.md`: General guidelines for human contributors. Your instructions here supersede this file.

### Documentation and Reference Documents
* 

---

## 2. Development Workflow & Testing

Adherence to this workflow is **mandatory** for all code contributions.

### Setup

1.  Create and activate a Python virtual environment.
2.  Install all required development dependencies using the `requirements.txt` file:
    ```bash
    pip install -r requirements.txt
    ```

### Code Style & Linting

* This project uses **pylint** to enforce code style and detect potential errors.
* Before submitting code, you **must** run the linter and ensure your changes do not introduce any new errors.
* Run the linter from the repository's root directory with the following command:
    ```bash
    ./lint.sh all   # Lint all source files
    ```
    or 
    ```bash
    ./lint.sh   # Lint locally modified source files
    ```

### Testing Protocol

* **All code changes require corresponding tests.** This is a strict requirement.
    * Bug fixes **should** include a new test that fails without the fix and passes with it.
    * New features **must** have comprehensive tests covering their functionality.
* The project includes 2 test suits:
    * Unit tests
    * Integration tests (Requires a real firebase project and credentials)
* Run the unit test suite using `pytest` from the root directory.
* Integration tests should only be run locally when credentials are avaiable and otherwise should be should be ignored.
    * If needed, integration tests can be run on Pull Request creation by the repository's GitHub Actions.
* **All tests must pass** before a Pull Request can be submitted. 
* Tests requiring network calls maybe mocked where appropriate.

---

## 3. Coding Conventions & Architectural Principles

* **Internal vs. Public API**: Public functions and classes are denoted by names without an underscore prefix unless superseded by an `__all__` variable. Helper functions and internal logic should be prefixed with an underscore (e.g., `_get_user_claims`).

---

## 4. Contribution and Pull Request Process

### Branching and Committing

1.  **Branching**: When creeating a new barnch use the format `<AgentName>-short-description`.
    * Example: `jules-auth-token-parsing`
    * Example: `gemini-add-storage-file-signer`
2.  **Commit Messages**: Make your commit messages clear and descriptive.

### Pull Request (PR) Generation

When you have finished implementing and testing a change, generate a Pull Request following these rules:

1.  **PR Title**: Use the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification.
    * Format: `type(scope): subject`
    * `scope` should be the service module you changed (e.g., `auth`, `firestore`, `fcm`, `deps`).
    * Example: `fix(auth): Corrected token expiration check for leap years`
    * Example: `feat(storage): Added support for generating signed URLs`
2.  **PR Description**: The description body must contain:
    * A brief explanation of the problem and the solution.
    * A summary of the testing strategy (e.g., "Added a new unit test in `tests/test_auth.py` to replicate the bug and verify the fix.").
3.  **Context Reporting**: At the end of every PR description, you MUST include a "Context Sources" section that lists the `id` and repository path of every `AGENTS.md` file you used. Format it like this:
    * Example: \
        **Context Sources Used:**
        - `id: firebase-admin-python` (`/AGENTS.md`)
        - `id: firebase-admin-python-auth` (`/firebase_admin/auth/AGENTS.md`)