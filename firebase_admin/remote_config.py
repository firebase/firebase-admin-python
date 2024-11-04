# Copyright 2017 Google Inc.
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

"""Firebase Remote Config Module.
This module has required APIs for the clients to use Firebase Remote Config with python.
"""

import json
import logging
from typing import Dict, Optional, Literal, Callable, Union
from enum import Enum
import re
import hashlib
from firebase_admin import App, _http_client, _utils
import firebase_admin

# Set up logging (you can customize the level and output)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_REMOTE_CONFIG_ATTRIBUTE = '_remoteconfig'
MAX_CONDITION_RECURSION_DEPTH = 10
ValueSource = Literal['default', 'remote', 'static']  # Define the ValueSource type
class PercentConditionOperator(Enum):
    """Enum representing the available operators for percent conditions.
    """
    LESS_OR_EQUAL = "LESS_OR_EQUAL"
    GREATER_THAN = "GREATER_THAN"
    BETWEEN = "BETWEEN"
    UNKNOWN = "UNKNOWN"

class CustomSignalOperator(Enum):
    """Enum representing the available operators for custom signal conditions.
    """
    STRING_CONTAINS = "STRING_CONTAINS"
    STRING_DOES_NOT_CONTAIN = "STRING_DOES_NOT_CONTAIN"
    STRING_EXACTLY_MATCHES = "STRING_EXACTLY_MATCHES"
    STRING_CONTAINS_REGEX = "STRING_CONTAINS_REGEX"
    NUMERIC_LESS_THAN = "NUMERIC_LESS_THAN"
    NUMERIC_LESS_EQUAL = "NUMERIC_LESS_EQUAL"
    NUMERIC_EQUAL = "NUMERIC_EQUAL"
    NUMERIC_NOT_EQUAL = "NUMERIC_NOT_EQUAL"
    NUMERIC_GREATER_THAN = "NUMERIC_GREATER_THAN"
    NUMERIC_GREATER_EQUAL = "NUMERIC_GREATER_EQUAL"
    SEMANTIC_VERSION_LESS_THAN = "SEMANTIC_VERSION_LESS_THAN"
    SEMANTIC_VERSION_LESS_EQUAL = "SEMANTIC_VERSION_LESS_EQUAL"
    SEMANTIC_VERSION_EQUAL = "SEMANTIC_VERSION_EQUAL"
    SEMANTIC_VERSION_NOT_EQUAL = "SEMANTIC_VERSION_NOT_EQUAL"
    SEMANTIC_VERSION_GREATER_THAN = "SEMANTIC_VERSION_GREATER_THAN"
    SEMANTIC_VERSION_GREATER_EQUAL = "SEMANTIC_VERSION_GREATER_EQUAL"
    UNKNOWN = "UNKNOWN"

class ServerTemplateData:
    """Represents a Server Template Data class."""
    def __init__(self, etag, template_data):
        """Initializes a new ServerTemplateData instance.

        Args:
            etag: The string to be used for initialize the ETag property.
            template_data: The data to be parsed for getting the parameters and conditions.
        """
        self._parameters = template_data['parameters']
        self._conditions = template_data['conditions']
        self._version = template_data['version']
        self._parameter_groups = template_data['parameterGroups']
        self._etag = etag

    @property
    def parameters(self):
        return self._parameters

    @property
    def etag(self):
        return self._etag

    @property
    def version(self):
        return self._version

    @property
    def conditions(self):
        return self._conditions

    @property
    def parameter_groups(self):
        return self._parameter_groups


class ServerTemplate:
    """Represents a Server Template with implementations for loading and evaluting the tempalte."""
    def __init__(self, app: App = None, default_config: Optional[Dict[str, str]] = None):
        """Initializes a ServerTemplate instance.

        Args:
          app: App instance to be used. This is optional and the default app instance will
                be used if not present.
          default_config: The default config to be used in the evaluated config.
        """
        self._rc_service = _utils.get_app_service(app,
                                                  _REMOTE_CONFIG_ATTRIBUTE, _RemoteConfigService)
        # This gets set when the template is
        # fetched from RC servers via the load API, or via the set API.
        self._cache = None
        if default_config is not None:
            self._stringified_default_config = json.dumps(default_config)
        else:
            self._stringified_default_config = None

    async def load(self):
        """Fetches the server template and caches the data."""
        self._cache = await self._rc_service.getServerTemplate()

    def evaluate(self, context: Optional[Dict[str, Union[str, int]]] = None) -> 'ServerConfig':
        """Evaluates the cached server template to produce a ServerConfig.

        Args:
          context: A dictionary of values to use for evaluating conditions.

        Returns:
          A ServerConfig object.
        Raises:
            ValueError: If the input arguments are invalid.
        """
        # Logic to process the cached template into a ServerConfig here.
        # TODO: Add Condition evaluator.
        if not self._cache:
            raise ValueError("""No Remote Config Server template in cache.
                            Call load() before calling evaluate().""")
        context = context or {}
        config_values = {}
        # Initializes config Value objects with default values.
        if self._stringified_default_config is not None:
            for key, value in json.loads(self._stringified_default_config).items():
                config_values[key] = _Value('default', value)
        self._evaluator = _ConditionEvaluator(self._cache.conditions,
                                              self._cache.parameters, context,
                                              config_values)
        return ServerConfig(config_values=self._evaluator.evaluate())

    def set(self, template):
        """Updates the cache to store the given template is of type ServerTemplateData.

        Args:
          template: An object of type ServerTemplateData to be cached.
        """
        if isinstance(template, ServerTemplateData):
            self._cache = template


class ServerConfig:
    """Represents a Remote Config Server Side Config."""
    def __init__(self, config_values):
        self._config_values = config_values # dictionary of param key to values

    def get_boolean(self, key):
        return self.get_value(key).as_boolean()

    def get_string(self, key):
        return self.get_value(key).as_string()

    def get_int(self, key):
        return self.get_value(key).as_number()

    def get_value(self, key):
        return self._config_values[key]


class _RemoteConfigService:
    """Internal class that facilitates sending requests to the Firebase Remote
        Config backend API.
    """
    def __init__(self, app):
        """Initialize a JsonHttpClient with necessary inputs.

        Args:
            app: App instance to be used for fetching app specific details required
                for initializing the http client.
        """
        remote_config_base_url = 'https://firebaseremoteconfig.googleapis.com'
        self._project_id = app.project_id
        app_credential = app.credential.get_credential()
        rc_headers = {
            'X-FIREBASE-CLIENT': 'fire-admin-python/{0}'.format(firebase_admin.__version__), }
        timeout = app.options.get('httpTimeout', _http_client.DEFAULT_TIMEOUT_SECONDS)

        self._client = _http_client.JsonHttpClient(credential=app_credential,
                                                   base_url=remote_config_base_url,
                                                   headers=rc_headers, timeout=timeout)


    def get_server_template(self):
        """Requests for a server template and converts the response to an instance of
        ServerTemplateData for storing the template parameters and conditions."""
        url_prefix = self._get_url_prefix()
        headers, response_json = self._client.headers_and_body('get',
                                                               url=url_prefix+'/namespaces/ \
                                                               firebase-server/serverRemoteConfig')
        return ServerTemplateData(headers.get('ETag'), response_json)

    def _get_url_prefix(self):
        # Returns project prefix for url, in the format of
        # /v1/projects/${projectId}
        return "/v1/projects/{0}".format(self._project_id)


class _ConditionEvaluator:
    """Internal class that facilitates sending requests to the Firebase Remote
    Config backend API."""
    def __init__(self, conditions, parameters, context, config_values):
        self._context = context
        self._conditions = conditions
        self._parameters = parameters
        self._config_values = config_values

    def evaluate(self):
        """Internal function Evaluates the cached server template to produce
        a ServerConfig"""
        evaluated_conditions = self.evaluate_conditions(self._conditions, self._context)

        # Overlays config Value objects derived by evaluating the template.
       # evaluated_conditions = None
        if self._parameters is not None:
            for key, parameter in self._parameters.items():
                conditional_values = parameter.get('conditionalValues', {})
                default_value = parameter.get('defaultValue', {})
                parameter_value_wrapper = None
                # Iterates in order over condition list. If there is a value associated
                # with a condition, this checks if the condition is true.
                if evaluated_conditions is not None:
                    for condition_name, condition_evaluation in evaluated_conditions.items():
                        if condition_name in conditional_values and condition_evaluation:
                            parameter_value_wrapper = conditional_values[condition_name]
                            break

                if parameter_value_wrapper and parameter_value_wrapper.get('useInAppDefault'):
                    logger.info("Using in-app default value for key '%s'", key)
                    continue

                if parameter_value_wrapper:
                    parameter_value = parameter_value_wrapper.get('value')
                    self._config_values[key] = _Value('remote', parameter_value)
                    continue

                if not default_value:
                    logger.warning("No default value found for key '%s'", key)
                    continue

                if default_value.get('useInAppDefault'):
                    logger.info("Using in-app default value for key '%s'", key)
                    continue
                self._config_values[key] = _Value('remote', default_value.get('value'))
        return self._config_values

    def evaluate_conditions(self, conditions, context)-> Dict[str, bool]:
        """Evaluates a list of conditions and returns a dictionary of results.

        Args:
          conditions: A list of NamedCondition objects.
          context: An EvaluationContext object.

        Returns:
          A dictionary mapping condition names to boolean evaluation results.
        """
        evaluated_conditions = {}
        for condition in conditions:
            evaluated_conditions[condition.get('name')] = self.evaluate_condition(
                condition.get('condition'), context
            )
        return evaluated_conditions

    def evaluate_condition(self, condition, context,
                           nesting_level: int = 0) -> bool:
        """Recursively evaluates a condition.

        Args:
          condition: The condition to evaluate.
          context: An EvaluationContext object.
          nesting_level: The current recursion depth.

        Returns:
          The boolean result of the condition evaluation.
        """
        if nesting_level >= MAX_CONDITION_RECURSION_DEPTH:
            logger.warning("Maximum condition recursion depth exceeded.")
            return False
        if condition.get('orCondition') is not None:
            return self.evaluate_or_condition(condition.get('orCondition'),
                                              context, nesting_level + 1)
        if condition.get('andCondition') is not None:
            return self.evaluate_and_condition(condition.get('andCondition'),
                                               context, nesting_level + 1)
        if condition.get('true') is not None:
            return True
        if condition.get('false') is not None:
            return False
        if condition.get('percent') is not None:
            return self.evaluate_percent_condition(condition.get('percent'), context)
        if condition.get('customSignal') is not None:
            return self.evaluate_custom_signal_condition(condition.get('customSignal'), context)
        logger.warning("Unknown condition type encountered.")
        return False

    def evaluate_or_condition(self, or_condition,
                              context,
                              nesting_level: int = 0) -> bool:
        """Evaluates an OR condition.

        Args:
          or_condition: The OR condition to evaluate.
          context: An EvaluationContext object.
          nesting_level: The current recursion depth.

        Returns:
          True if any of the subconditions are true, False otherwise.
        """
        sub_conditions = or_condition.get('conditions') or []
        for sub_condition in sub_conditions:
            result = self.evaluate_condition(sub_condition, context, nesting_level + 1)
            if result:
                return True
        return False

    def evaluate_and_condition(self, and_condition,
                               context,
                               nesting_level: int = 0) -> bool:
        """Evaluates an AND condition.

        Args:
          and_condition: The AND condition to evaluate.
          context: An EvaluationContext object.
          nesting_level: The current recursion depth.

        Returns:
          True if all of the subconditions are true, False otherwise.
        """
        sub_conditions = and_condition.get('conditions') or []
        for sub_condition in sub_conditions:
            result = self.evaluate_condition(sub_condition, context, nesting_level + 1)
            if not result:
                return False
        return True

    def evaluate_percent_condition(self, percent_condition,
                                   context) -> bool:
        """Evaluates a percent condition.

        Args:
          percent_condition: The percent condition to evaluate.
          context: An EvaluationContext object.

        Returns:
          True if the condition is met, False otherwise.
        """
        if not context.get('randomization_id'):
            logger.warning("Missing randomization ID for percent condition.")
            return False

        seed = percent_condition.get('seed')
        percent_operator = percent_condition.get('percentOperator')
        micro_percent = percent_condition.get('microPercent')
        micro_percent_range = percent_condition.get('microPercentRange')
        if not percent_operator:
            logger.warning("Missing percent operator for percent condition.")
            return False
        if micro_percent_range:
            norm_percent_upper_bound = micro_percent_range.get('microPercentUpperBound')
            norm_percent_lower_bound = micro_percent_range.get('microPercentLowerBound')
        else:
            norm_percent_upper_bound = 0
            norm_percent_lower_bound = 0
        seed_prefix = f"{seed}." if seed else ""
        string_to_hash = f"{seed_prefix}{context.get('randomization_id')}"

        hash64 = self.hash_seeded_randomization_id(string_to_hash)
        instance_micro_percentile = hash64 % (100 * 1000000)
        if percent_operator == PercentConditionOperator.LESS_OR_EQUAL:
            return instance_micro_percentile <= micro_percent
        if percent_operator == PercentConditionOperator.GREATER_THAN:
            return instance_micro_percentile > micro_percent
        if percent_operator == PercentConditionOperator.BETWEEN:
            return norm_percent_lower_bound < instance_micro_percentile <= norm_percent_upper_bound
        logger.warning("Unknown percent operator: %s", percent_operator)
        return False
    def hash_seeded_randomization_id(self, seeded_randomization_id: str) -> int:
        """Hashes a seeded randomization ID.

        Args:
          seeded_randomization_id: The seeded randomization ID to hash.

        Returns:
          The hashed value.
        """
        hash_object = hashlib.sha256()
        hash_object.update(seeded_randomization_id.encode('utf-8'))
        hash64 = hash_object.hexdigest()
        return abs(int(hash64, 16))
    def evaluate_custom_signal_condition(self, custom_signal_condition,
                                         context) -> bool:
        """Evaluates a custom signal condition.

        Args:
          custom_signal_condition: The custom signal condition to evaluate.
          context: An EvaluationContext object.

        Returns:
          True if the condition is met, False otherwise.
        """
        custom_signal_operator = custom_signal_condition.get('custom_signal_operator') or {}
        custom_signal_key = custom_signal_condition.get('custom_signal_key') or {}
        tgt_custom_signal_values = custom_signal_condition.get('target_custom_signal_values') or {}

        if not all([custom_signal_operator, custom_signal_key, tgt_custom_signal_values]):
            logger.warning("Missing operator, key, or target values for custom signal condition.")
            return False

        if not tgt_custom_signal_values:
            return False
        actual_custom_signal_value = getattr(context, custom_signal_key, None)
        if actual_custom_signal_value is None:
            logger.warning("Custom signal value not found in context: %s", custom_signal_key)
            return False
        if custom_signal_operator == CustomSignalOperator.STRING_CONTAINS:
            return compare_strings(lambda target, actual: target in actual)
        if custom_signal_operator == CustomSignalOperator.STRING_DOES_NOT_CONTAIN:
            return not compare_strings(lambda target, actual: target in actual)
        if custom_signal_operator == CustomSignalOperator.STRING_EXACTLY_MATCHES:
            return compare_strings(lambda target, actual: target.strip() == actual.strip())
        if custom_signal_operator == CustomSignalOperator.STRING_CONTAINS_REGEX:
            return compare_strings(lambda target, actual: re.search(target, actual) is not None)
        if custom_signal_operator == CustomSignalOperator.NUMERIC_LESS_THAN:
            return compare_numbers(lambda r: r < 0)
        if custom_signal_operator == CustomSignalOperator.NUMERIC_LESS_EQUAL:
            return compare_numbers(lambda r: r <= 0)
        if custom_signal_operator == CustomSignalOperator.NUMERIC_EQUAL:
            return compare_numbers(lambda r: r == 0)
        if custom_signal_operator == CustomSignalOperator.NUMERIC_NOT_EQUAL:
            return compare_numbers(lambda r: r != 0)
        if custom_signal_operator == CustomSignalOperator.NUMERIC_GREATER_THAN:
            return compare_numbers(lambda r: r > 0)
        if custom_signal_operator == CustomSignalOperator.NUMERIC_GREATER_EQUAL:
            return compare_numbers(lambda r: r >= 0)
        if custom_signal_operator == CustomSignalOperator.SEMANTIC_VERSION_LESS_THAN:
            return compare_semantic_versions(lambda r: r < 0)
        if custom_signal_operator == CustomSignalOperator.SEMANTIC_VERSION_LESS_EQUAL:
            return compare_semantic_versions(lambda r: r <= 0)
        if custom_signal_operator == CustomSignalOperator.SEMANTIC_VERSION_EQUAL:
            return compare_semantic_versions(lambda r: r == 0)
        if custom_signal_operator == CustomSignalOperator.SEMANTIC_VERSION_NOT_EQUAL:
            return compare_semantic_versions(lambda r: r != 0)
        if custom_signal_operator == CustomSignalOperator.SEMANTIC_VERSION_GREATER_THAN:
            return compare_semantic_versions(lambda r: r > 0)
        if custom_signal_operator == CustomSignalOperator.SEMANTIC_VERSION_GREATER_EQUAL:
            return compare_semantic_versions(lambda r: r >= 0)

        def compare_strings(predicate_fn: Callable[[str, str], bool]) -> bool:
            """Compares the actual string value of a signal against a list of target values.

            Args:
                predicate_fn: A function that takes two string arguments (target and actual)
                                and returns a boolean indicating whether
                                the target matches the actual value.

            Returns:
                bool: True if the predicate function returns True for any target value in the list,
                    False otherwise.
            """
            for target in tgt_custom_signal_values:
                if predicate_fn(target, str(actual_custom_signal_value)):
                    return True
            return False

        def compare_numbers(predicate_fn: Callable[[int], bool]) -> bool:
            try:
                target = float(tgt_custom_signal_values[0])
                actual = float(actual_custom_signal_value)
                result = -1 if actual < target else 1 if actual > target else 0
                return predicate_fn(result)
            except ValueError:
                logger.warning("Invalid numeric value for comparison.")
                return False

        def compare_semantic_versions(predicate_fn: Callable[[int], bool]) -> bool:
            """Compares the actual semantic version value of a signal against a target value.
            Calls the predicate function with -1, 0, 1 if actual is less than, equal to,
            or greater than target.

            Args:
            predicate_fn: A function that takes an integer (-1, 0, or 1) and returns a boolean.

            Returns:
                bool: True if the predicate function returns True for the result of the comparison,
            False otherwise.
            """
            return compare_versions(str(actual_custom_signal_value),
                                    str(tgt_custom_signal_values[0]), predicate_fn)
        def compare_versions(version1: str, version2: str,
                             predicate_fn: Callable[[int], bool]) -> bool:
            """Compares two semantic version strings.

            Args:
            version1: The first semantic version string.
            version2: The second semantic version string.
            predicate_fn: A function that takes an integer and returns a boolean.

            Returns:
                bool: The result of the predicate function.
            """
            try:
                v1_parts = [int(part) for part in version1.split('.')]
                v2_parts = [int(part) for part in version2.split('.')]
                max_length = max(len(v1_parts), len(v2_parts))
                v1_parts.extend([0] * (max_length - len(v1_parts)))
                v2_parts.extend([0] * (max_length - len(v2_parts)))

                for part1, part2 in zip(v1_parts, v2_parts):
                    if part1 < part2:
                        return predicate_fn(-1)
                    if part1 > part2:
                        return predicate_fn(1)
                return predicate_fn(0)
            except ValueError:
                logger.warning("Invalid semantic version format for comparison.")
                return False

        logger.warning("Unknown custom signal operator: %s", custom_signal_operator)
        return False

async def get_server_template(app: App = None, default_config: Optional[Dict[str, str]] = None):
    """Initializes a new ServerTemplate instance and fetches the server template.

    Args:
        app: App instance to be used. This is optional and the default app instance will
            be used if not present.
        default_config: The default config to be used in the evaluated config.

    Returns:
        ServerTemplate: An object having the cached server template to be used for evaluation.
    """
    template = init_server_template(app=app, default_config=default_config)
    await template.load()
    return template

def init_server_template(app: App = None, default_config: Optional[Dict[str, str]] = None,
                         template_data: Optional[ServerTemplateData] = None):
    """Initializes a new ServerTemplate instance.

    Args:
        app: App instance to be used. This is optional and the default app instance will
            be used if not present.
        default_config: The default config to be used in the evaluated config.
        template_data: An optional template data to be set on initialization.

    Returns:
        ServerTemplate: A new ServerTemplate instance initialized with an optional
        template and config.
    """
    template = ServerTemplate(app=app, default_config=default_config)
    if template_data is not None:
        template.set(template_data)
    return template

class _Value:
    """Represents a value fetched from Remote Config.
    """
    DEFAULT_VALUE_FOR_BOOLEAN = False
    DEFAULT_VALUE_FOR_STRING = ''
    DEFAULT_VALUE_FOR_NUMBER = 0
    BOOLEAN_TRUTHY_VALUES = ['1', 'true', 't', 'yes', 'y', 'on']

    def __init__(self, source: ValueSource, value: str = DEFAULT_VALUE_FOR_STRING):
        """Initializes a Value instance.

        Args:
          source: The source of the value (e.g., 'default', 'remote', 'static').
          value: The string value.
        """
        self.source = source
        self.value = value

    def as_string(self) -> str:
        """Returns the value as a string."""
        return self.value

    def as_boolean(self) -> bool:
        """Returns the value as a boolean."""
        if self.source == 'static':
            return self.DEFAULT_VALUE_FOR_BOOLEAN
        return str(self.value).lower() in self.BOOLEAN_TRUTHY_VALUES

    def as_number(self) -> float:
        """Returns the value as a number."""
        if self.source == 'static':
            return self.DEFAULT_VALUE_FOR_NUMBER
        try:
            return float(self.value)
        except ValueError:
            return self.DEFAULT_VALUE_FOR_NUMBER

    def get_source(self) -> ValueSource:
        """Returns the source of the value."""
        return self.source
