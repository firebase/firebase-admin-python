# Contributing | Firebase Admin Python SDK

Thank you for contributing to the Firebase community!

 - [Have a usage question?](#question)
 - [Think you found a bug?](#issue)
 - [Have a feature request?](#feature)
 - [Want to submit a pull request?](#submit)
 - [Need to get set up locally?](#local-setup)


## <a name="question"></a>Have a usage question?

We get lots of those and we love helping you, but GitHub is not the best place for them. Issues
which just ask about usage will be closed. Here are some resources to get help:

- Go through the [guides](https://firebase.google.com/docs/admin/setup/)
- Read the full [API reference](https://firebase.google.com/docs/reference/admin/python/)

If the official documentation doesn't help, try asking a question on the
[Firebase Google Group](https://groups.google.com/forum/#!forum/firebase-talk/) or one of our
other [official support channels](https://firebase.google.com/support/).

**Please avoid double posting across multiple channels!**


## <a name="issue"></a>Think you found a bug?

Yeah, we're definitely not perfect!

Search through [old issues](https://github.com/firebase/firebase-admin-python/issues) before
submitting a new issue as your question may have already been answered.

If your issue appears to be a bug, and hasn't been reported,
[open a new issue](https://github.com/firebase/firebase-admin-python/issues/new). Please use the
provided bug report template and include a minimal repro.

If you are up to the challenge, [submit a pull request](#submit) with a fix!


## <a name="feature"></a>Have a feature request?

Great, we love hearing how we can improve our products! Share you idea through our
[feature request support channel](https://firebase.google.com/support/contact/bugs-features/).


## <a name="submit"></a>Want to submit a pull request?

Sweet, we'd love to accept your contribution!
[Open a new pull request](https://github.com/firebase/firebase-admin-python/pull/new/master) and fill
out the provided template.

**If you want to implement a new feature, please open an issue with a proposal first so that we can
figure out if the feature makes sense and how it will work.**

Make sure your changes pass our linter and the tests all pass on your local machine.
Most non-trivial changes should include some extra test coverage. If you aren't sure how to add
tests, feel free to submit regardless and ask us for some advice.

Finally, you will need to sign our
[Contributor License Agreement](https://cla.developers.google.com/about/google-individual),
and go through our code review process before we can accept your pull request.

### Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License
Agreement. You (or your employer) retain the copyright to your contribution.
This simply gives us permission to use and redistribute your contributions as
part of the project. Head over to <https://cla.developers.google.com/> to see
your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one
(even if it was for a different project), you probably don't need to do it
again.

### Code reviews

All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose. Consult
[GitHub Help](https://help.github.com/articles/about-pull-requests/) for more
information on using pull requests.


## <a name="local-setup"></a>Need to get set up locally?

### Initial Setup

You need Python 3.4+ to build and test the code in this repo.

We recommend using [pip](https://pypi.python.org/pypi/pip) for installing the necessary tools and
project dependencies. Most recent versions of Python ship with pip. If your development environment
does not already have pip, use the software package manager of your platform (e.g. apt-get, brew)
to download and install it. Alternatively you may also follow the official
[pip installation guide](https://pip.pypa.io/en/stable/installing/).

Once pip is installed, run the following commands from the command line to get your local
environment set up:

```bash
$ git clone https://github.com/firebase/firebase-admin-python.git
$ cd firebase-admin-python         # go to the firebase-admin-python directory
$ pip install -r requirements.txt  # Install additional tools and dependencies
```

### Running Linters

We use [pylint](https://pylint.org/) for verifying source code format, and
enforcing other Python programming best practices.
There is a pylint configuration file ([`.pylintrc`](.pylintrc)) at the root of this Git
repository. This enables you to invoke pylint directly from the command line:

```
pylint firebase_admin
```

However, it is recommended that you use the [`lint.sh`](lint.sh) bash script to invoke
pylint. This script will run the linter on both `firebase_admin` and the corresponding
`tests` module. It suppresses some of the noisy warnings that get generated
when running pylint on test code. Note that by default `lint.sh` will only
validate the locally modified source files. To validate all source files,
pass `all` as an argument.

```
./lint.sh      # Lint locally modified source files
./lint.sh all  # Lint all source files
```

Ideally you should not see any pylint errors or warnings when you run the
linter. This means source files are properly formatted, and the linter has
not found any issues. If you do observe any errors, fix them before
committing or sending a pull request. Details on how to interpret pylint
errors are available
[here](https://pylint.readthedocs.io/en/latest/user_guide/output.html).

Our configuration files suppress the verbose reports usually generated
by pylint, and only output the detected issues. If you wish to obtain the
comprehensive reports, run pylint from command-line with the `-r` flag.

```
pylint -r yes firebase_admin
```

### Unit Testing

We use [pytest](http://doc.pytest.org/en/latest/) for writing and executing
unit tests. All source files containing test code is located in the `tests/`
directory. Simply launch pytest from the root of the Git repository, or from
within the `tests/` directory to execute all test cases.

```
pytest
```

Refer to the pytest [usage and invocations guide](http://doc.pytest.org/en/latest/usage.html)
to learn how to run a subset of all test cases.

You can also get a code coverage report by launching pytest as follows:

```
pytest --cov=firebase_admin --cov=tests
```

### Integration Testing

A suite of integration tests are available under the `integration/` directory.
These tests are designed to run against an actual Firebase project. Create a new
project in the [Firebase Console](https://console.firebase.google.com), if you
do not already have one suitable for running the tests aginst. Then obtain the
following credentials from the project:

1. *Service account certificate*: This can be downloaded as a JSON file from
   the "Settings > Service Accounts" tab of the Firebase console. Copy the
   file into the repo so it's available at `cert.json`.
2. *Web API key*: This is displayed in the "Settings > General" tab of the
   console. Copy it and save to a new text file at `apikey.txt`.

Then set up your Firebase/GCP project as follows:

1. Enable Firestore: Go to the Firebase Console, and select "Database" from
   the "Develop" menu. Click on the "Create database" button. You may choose
   to set up Firestore either in the locked mode or in the test mode.
2. Enable password auth: Select "Authentication" from the "Develop" menu in
   Firebase Console. Select the "Sign-in method" tab, and enable the
   "Email/Password" sign-in method, including the Email link (passwordless
   sign-in) option.
3. Enable the Firebase ML API: Go to the
   [Google Developers Console](
   https://console.developers.google.com/apis/api/firebaseml.googleapis.com/overview)
   and make sure your project is selected. If the API is not already enabled, click Enable.
4. Enable the IAM API: Go to the
   [Google Cloud Platform Console](https://console.cloud.google.com) and make
   sure your Firebase/GCP project is selected. Select "APIs & Services >
   Dashboard" from the main menu, and click the "ENABLE APIS AND SERVICES"
   button. Search for and enable the "Identity and Access Management (IAM)
   API".
5. Grant your service account the 'Firebase Authentication Admin' role. This is
   required to ensure that exported user records contain the password hashes of
   the user accounts:
   1. Go to [Google Cloud Platform Console / IAM & admin](https://console.cloud.google.com/iam-admin).
   2. Find your service account in the list, and click the 'pencil' icon to edit it's permissions.
   3. Click 'ADD ANOTHER ROLE' and choose 'Firebase Authentication Admin'.
   4. Click 'SAVE'.


Now you can invoke the integration test suite as follows:

```
pytest integration/ --cert cert.json --apikey apikey.txt
```

### Emulator-based Integration Testing

Some integration tests can run against emulators. This allows local testing
without using real projects or credentials. For now, only the RTDB Emulator
is supported.

First, install the Firebase CLI, then run:

```
firebase emulators:exec --only database --project fake-project-id 'pytest integration/test_db.py'
```

### Test Coverage

To review the test coverage, run `pytest` with the `--cov` flag. To view a detailed line by line
coverage, use
```bash
pytest --cov --cov-report html
```
and point your browser to
`file:///<dir>/htmlcov/index.html` (where `dir` is the location from which the report was created).

### Repo Organization

Here are some highlights of the directory structure and notable source files

* `firebase_admin/` - Source directory for the `firebase_admin` module.
* `integration/` - Integration tests.
* `tests/` - Unit tests.
  * `data/` - Provides mocks for several variables as well as mock service account keys.
* `scripts/` - A collection of shell scripts used to create and verify releases.
* `.github/` - Contribution instructions as well as issue and pull request templates.
* `lint.sh` - Runs pylint to check for code quality.
* `.pylintrc` - Default configuration for pylint.
* `requirements.txt` - Requirements specification for installing project dependencies via pip.
* `setup.py` - Python setup script for building distribution artifacts.
* `tox.ini` - Tox configuration for running tests on different environments.
