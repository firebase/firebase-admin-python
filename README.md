# Firebase Admin Python SDK

## Running Linters
We use [pylint](https://pylint.org/) for verifying source code format,
and enforcing other Python programming best practices. Install pylint
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

There is a pylint configuration file (`.pylintrc`) at the root of this Git
repository. This enables you to invoke pylint directly from the command line.

```
pylint firebase
```

However, it is recommended that you use the `lint.sh` bash script to invoke
pylint. This script will run the linter on both firebase and the corresponding
tests module. It suprresses some of the noisy warnings that get generated
when running pylint on test code. Note that by default `lint.sh` will only
validate the locally modified source files. To validate all source files,
pass `all` as an argument.

```
./lint.sh
./lint.sh all
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
