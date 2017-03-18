# Firebase Admin Python SDK

## Running Linters
We recommend using [pylint](https://pylint.org/) for verifying source code
format, and enforcing other Python programming best practices. Install pylint
1.6.4 or higher using pip.

```
sudo pip install pylint
```

Specify a pylint version explicitly if the above command installs an older 
version.

```
sudo pip install pylint==1.6.4
```

Once installed, you can check the version of the installed binary by running
the following command.

```
pylint --version
```

There are two pylint configuration files at the root of this repository.
 * .pylintrc: Settings for validating the source files in firebase module.
 * .test_pylintrc: Settings for validating the test files. This is a marginally
    relaxed version of .pylintrc.
    
You can run pylint directly using the above configuration files.

```
pylint --rcfile .pylintrc firebase
pylint --rcfile .test_pylintrc tests
```

Alternatively you can use the `lint.sh` bash script to invoke pylint. By default
this script will only validate the locally modified source files. To validate
all source files, pass `all` as an argument.

```
./lint.sh
./lint.sh all
```

Ideally you should not see any pylint errors or warnings when you run the linter.
This means source files are properly formatted, and the linter has not found any
issues. If you do observe any errors, fix them before sending a pull request.
Details on how to interpret pylint errors are available here 
[here](https://pylint.readthedocs.io/en/latest/user_guide/output.html).
