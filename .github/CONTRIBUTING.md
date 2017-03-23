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
[Contributor License Agreement](https://cla.developers.google.com/about/google-individual)
before we can accept your pull request.


## <a name="local-setup"></a>Need to get set up locally?


### Initial Setup

Run the following commands from the command line to get your local environment set up:

```bash
$ git clone https://github.com/firebase/firebase-admin-python.git
$ cd firebase-admin-python                 # go to the firebase-admin-python directory
$ pip install -r .github/requirements.txt  # Install additional tools and dependencies
```

### Running Linters

We use [pylint](https://pylint.org/) for verifying source code format, and
enforcing other Python programming best practices.
There is a pylint configuration file (`.pylintrc`) at the root of this Git
repository. This enables you to invoke pylint directly from the command line:

```
pylint firebase
```

However, it is recommended that you use the `lint.sh` bash script to invoke
pylint. This script will run the linter on both `firebase` and the corresponding
`tests` module. It suprresses some of the noisy warnings that get generated
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
pylint -r yes firebase
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

### Testing on Different Platforms

Sometimes we may want to run unit tests in multiple environments (e.g. different
Python versions), and ensure that the SDK works as expected in each of them.
We use [tox](https://tox.readthedocs.io/en/latest/) for this purpose.
You can execute the following command from the root of the repository to
launch tox:

```
tox
```

This command will read a list of target environments from the [`tox.ini`](../tox.ini)
file in the Git repository, and execute test cases in each of those environments.

### Repo Organization

Here are some highlights of the directory structure and notable source files

* `firebase/` - Source directory for the `firebase` module.
* `tests/` - Unit tests.
  * `data/` - Provides mocks for several variables as well as mock service account keys.
* `.github/` - Contribution instructions as well as issue and pull request templates.
* `lint.sh` - Runs pylint to check for code quality.
* `.pylintrc` - Default configuration for pylint.
* `setup.py` - Python setup script for building distribution artifacts.
* `tox.ini` - Tox configuration for running tests on different environments.
