"""Firebase Admin SDK for Python."""
import threading

import six

from firebase_admin import credentials


_apps = {}
_apps_lock = threading.RLock()

_DEFAULT_APP_NAME = '[DEFAULT]'


def initialize_app(credential=None, options=None, name=_DEFAULT_APP_NAME):
    """Initializes and returns a new App instance.

    Creates a new App intance using the specified options
    and the app name. If an instance already exists by the same
    app name a ValueError is raised. Use this function whenever
    a new App instance is required. Do not directly invoke the
    App constructor.

    Args:
      credential: A credential object used to initialize the SDK (optional). If none is provided,
      Google Application Default Credentials are used.
      options: A dictionary of configuration options (optional).
      name: Name of the app (optional).

    Returns:
      A newly initialized instance of App.

    Raises:
      ValueError: If the app name is already in use, or any of the
      provided arguments are invalid.
    """
    if credential is None:
        credential = credentials.ApplicationDefault()
    app = App(name, credential, options)
    with _apps_lock:
        if app.name not in _apps:
            _apps[app.name] = app
            return app

    if name == _DEFAULT_APP_NAME:
        raise ValueError((
            'The default Firebase app already exists. This means you called '
            'initialize_app() more than once without providing an app name as '
            'the second argument. In most cases you only need to call '
            'initialize_app() once. But if you do want to initialize multiple '
            'apps, pass a second argument to initialize_app() to give each app '
            'a unique name.'))
    else:
        raise ValueError((
            'Firebase app named "{0}" already exists. This means you called '
            'initialize_app() more than once with the same app name as the '
            'second argument. Make sure you provide a unique name every time '
            'you call initialize_app().').format(name))


def delete_app(app):
    """Gracefully deletes an App instance.

    Args:
      app: The app instance to be deleted.

    Raises:
      ValueError: If the app is not initialized.
    """
    if not isinstance(app, App):
        raise ValueError('Illegal app argument type: "{}". Argument must be of '
                         'type App.'.format(type(app)))
    with _apps_lock:
        if _apps.get(app.name) is app:
            del _apps[app.name]
            return
    if app.name == _DEFAULT_APP_NAME:
        raise ValueError(
            'The default Firebase app is not initialized. Make sure to initialize '
            'the default app by calling initialize_app().')
    else:
        raise ValueError(
            ('Firebase app named "{0}" is not initialized. Make sure to initialize '
             'the app by calling initialize_app() with your app name as the '
             'second argument.').format(app.name))


def get_app(name=_DEFAULT_APP_NAME):
    """Retrieves an App instance by name.

    Args:
      name: Name of the App instance to retrieve (optional).

    Returns:
      An App instance.

    Raises:
      ValueError: If the specified name is not a string, or if the specified
      app does not exist.
    """
    if not isinstance(name, six.string_types):
        raise ValueError('Illegal app name argument type: "{}". App name '
                         'must be a string.'.format(type(name)))
    with _apps_lock:
        if name in _apps:
            return _apps[name]

    if name == _DEFAULT_APP_NAME:
        raise ValueError(
            'The default Firebase app does not exist. Make sure to initialize '
            'the SDK by calling initialize_app().')
    else:
        raise ValueError(
            ('Firebase app named "{0}" does not exist. Make sure to initialize '
             'the SDK by calling initialize_app() with your app name as the '
             'second argument.').format(name))


class _AppOptions(object):
    """A collection of configuration options for an App."""

    def __init__(self, options):
        if options is None:
            options = {}
        if not isinstance(options, dict):
            raise ValueError('Illegal Firebase app options type: {0}. Options '
                             'must be a dictionary.'.format(type(options)))
        self._options = options


class App(object):
    """The entry point for Firebase Python SDK.

       Represents a Firebase app, while holding the configuration and state
       common to all Firebase APIs.
    """

    def __init__(self, name, credential, options):
        """Constructs a new App using the provided name and options.

        Args:
          name: Name of the application.
          credential: A credential object.
          options: A dictionary of configuration options.

        Raises:
          ValueError: If an argument is None or invalid.
        """
        if not name or not isinstance(name, six.string_types):
            raise ValueError('Illegal Firebase app name "{0}" provided. App name must be a '
                             'non-empty string.'.format(name))
        self._name = name

        if not isinstance(credential, credentials.Base):
            raise ValueError('Illegal Firebase credential provided. App must be initialized '
                             'with a valid credential instance.')
        self._credential = credential
        self._options = _AppOptions(options)

    @property
    def name(self):
        return self._name

    @property
    def credential(self):
        return self._credential

    @property
    def options(self):
        return self._options
