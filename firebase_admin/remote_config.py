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
"""
Firebase Remote Config Module.
This module has required APIs
 for the clients to use Firebase Remote Config with python.
"""

import logging
from enum import Enum
from typing import Dict, Optional, Literal, List, Callable, Any, Union
import re
import farmhash
from firebase_admin import _http_client

# Set up logging (you can customize the level and output)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ValueSource = Literal['default', 'remote', 'static']  # Define the ValueSource type

MAX_CONDITION_RECURSION_DEPTH = 10

class PercentConditionOperator(Enum):
    """
    Enum representing the available operators for percent conditions.
    """
    LESS_OR_EQUAL = "LESS_OR_EQUAL"
    GREATER_THAN = "GREATER_THAN"
    BETWEEN = "BETWEEN"
    UNKNOWN = "UNKNOWN"


class CustomSignalOperator(Enum):
    """
    Enum representing the available operators for custom signal conditions.
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

class Condition:
    """
    Base class for conditions.
    """
    def __init__(self):
        # This is just a base class, so it doesn't need any attributes
        pass


class OrCondition(Condition):
    """
    Represents an OR condition.
    """
    def __init__(self, conditions: List[Condition]):
        super().__init__()
        self.conditions = conditions


class AndCondition(Condition):
    """
    Represents an AND condition.
    """
    def __init__(self, conditions: List[Condition]):
        super().__init__()
        self.conditions = conditions


class PercentCondition(Condition):
    """
    Represents a percent condition.
    """
    def __init__(self, seed: str, percent_operator: PercentConditionOperator, micro_percent: int, micro_percent_range: Optional[Dict[str, int]] = None):
        super().__init__()
        self.seed = seed
        self.percent_operator = percent_operator
        self.micro_percent = micro_percent
        self.micro_percent_range = micro_percent_range


class CustomSignalCondition(Condition):
    """
    Represents a custom signal condition.
    """
    def __init__(self, custom_signal_operator: CustomSignalOperator, custom_signal_key: str, target_custom_signal_values: List[Union[str, int, float]]):
        super().__init__()
        self.custom_signal_operator = custom_signal_operator
        self.custom_signal_key = custom_signal_key
        self.target_custom_signal_values = target_custom_signal_values


class OneOfCondition(Condition):
    """
    Represents a condition that can be one of several types.
    """
    def __init__(self, or_condition: Optional[OrCondition] = None, and_condition: Optional[AndCondition] = None, true_condition: Optional[bool] = None, false_condition: Optional[bool] = None, percent_condition: Optional[PercentCondition] = None, custom_signal_condition: Optional[CustomSignalCondition] = None):
        super().__init__()
        self.or_condition = or_condition
        self.and_condition = and_condition
        self.true_condition = true_condition
        self.false_condition = false_condition
        self.percent_condition = percent_condition
        self.custom_signal_condition = custom_signal_condition


class NamedCondition:
    """
    Represents a named condition.
    """
    def __init__(self, name: str, condition: OneOfCondition):
        self.name = name
        self.condition = condition


class EvaluationContext:
    """
    Represents the context for evaluating conditions.
    """
    def __init__(self, **kwargs):
        # This allows you to pass any key-value pairs to the context
        # For example: EvaluationContext(user_country="US", user_type="paid")
        self.__dict__.update(kwargs)

    def __getattr__(self, item):
        # This handles the case where a key is not found in the context
        return None

class ConditionEvaluator:
    """
    Encapsulates condition evaluation logic to simplify organization and
    facilitate testing.
    """

    def evaluate_conditions(self, named_conditions: List['NamedCondition'], context: 'EvaluationContext') -> Dict[str, bool]:
        """
        Evaluates a list of named conditions and returns a dictionary of results.

        Args:
          named_conditions: A list of NamedCondition objects.
          context: An EvaluationContext object.

        Returns:
          A dictionary mapping condition names to boolean evaluation results.
        """
        evaluated_conditions = {}
        for named_condition in named_conditions:
            evaluated_conditions[named_condition.name] = self.evaluate_condition(
                named_condition.condition, context)
        return evaluated_conditions

    def evaluate_condition(self, condition: 'OneOfCondition', context: 'EvaluationContext', nesting_level: int = 0) -> bool:
        """
        Recursively evaluates a condition.

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

        if condition.or_condition:
            return self.evaluate_or_condition(condition.or_condition, context, nesting_level + 1)
        if condition.and_condition:
            return self.evaluate_and_condition(condition.and_condition, context, nesting_level + 1)
        if condition.true_condition:
            return True
        if condition.false_condition:
            return False
        if condition.percent_condition:
            return self.evaluate_percent_condition(condition.percent_condition, context)
        if condition.custom_signal_condition:
            return self.evaluate_custom_signal_condition(condition.custom_signal_condition, context)
        
        logger.warning("Unknown condition type encountered.")
        return False

    def evaluate_or_condition(self, or_condition: 'OrCondition', context: 'EvaluationContext', nesting_level: int) -> bool:
        """
        Evaluates an OR condition.

        Args:
          or_condition: The OR condition to evaluate.
          context: An EvaluationContext object.
          nesting_level: The current recursion depth.

        Returns:
          True if any of the subconditions are true, False otherwise.
        """
        sub_conditions = or_condition.conditions or []
        for sub_condition in sub_conditions:
            result = self.evaluate_condition(sub_condition, context, nesting_level + 1)
            if result:
                return True
        return False

    def evaluate_and_condition(self, and_condition: 'AndCondition', context: 'EvaluationContext', nesting_level: int) -> bool:
        """
        Evaluates an AND condition.

        Args:
          and_condition: The AND condition to evaluate.
          context: An EvaluationContext object.
          nesting_level: The current recursion depth.

        Returns:
          True if all of the subconditions are true, False otherwise.
        """
        sub_conditions = and_condition.conditions or []
        for sub_condition in sub_conditions:
            result = self.evaluate_condition(sub_condition, context, nesting_level + 1)
            if not result:
                return False
        return True

    def evaluate_percent_condition(self, percent_condition: 'PercentCondition', context: 'EvaluationContext') -> bool:
        """
        Evaluates a percent condition.

        Args:
          percent_condition: The percent condition to evaluate.
          context: An EvaluationContext object.

        Returns:
          True if the condition is met, False otherwise.
        """
        if not context.randomization_id:
            logger.warning("Missing randomization ID for percent condition.")
            return False

        seed = percent_condition.seed
        percent_operator = percent_condition.percent_operator 
        micro_percent = percent_condition.micro_percent or 0
        micro_percent_range = percent_condition.micro_percent_range

        if not percent_operator:
            logger.warning("Missing percent operator for percent condition.")
            return False

        normalized_micro_percent_upper_bound = micro_percent_range.micro_percent_upper_bound if micro_percent_range else 0
        normalized_micro_percent_lower_bound = micro_percent_range.micro_percent_lower_bound if micro_percent_range else 0

        seed_prefix = f"{seed}." if seed else ""
        string_to_hash = f"{seed_prefix}{context.randomization_id}"

        hash64 = ConditionEvaluator.hash_seeded_randomization_id(string_to_hash)

        instance_micro_percentile = hash64 % (100 * 1_000_000)

        if percent_operator == "LESS_OR_EQUAL":
            return instance_micro_percentile <= micro_percent
        elif percent_operator == "GREATER_THAN":
            return instance_micro_percentile > micro_percent
        elif percent_operator == "BETWEEN":
            return normalized_micro_percent_lower_bound < instance_micro_percentile <= normalized_micro_percent_upper_bound
        else:
            logger.warning("Unknown percent operator: %s", percent_operator)
            return False

    @staticmethod
    def hash_seeded_randomization_id(seeded_randomization_id: str) -> int:
        """
        Hashes a seeded randomization ID.

        Args:
          seeded_randomization_id: The seeded randomization ID to hash.

        Returns:
          The hashed value.
        """
        hash64 = farmhash.fingerprint64(seeded_randomization_id)
        return abs(hash64)

    def evaluate_custom_signal_condition(self, custom_signal_condition: 'CustomSignalCondition', context: 'EvaluationContext') -> bool:
        """
        Evaluates a custom signal condition.

        Args:
          custom_signal_condition: The custom signal condition to evaluate.
          context: An EvaluationContext object.

        Returns:
          True if the condition is met, False otherwise.
        """
        custom_signal_operator = custom_signal_condition.custom_signal_operator
        custom_signal_key = custom_signal_condition.custom_signal_key
        target_custom_signal_values = custom_signal_condition.target_custom_signal_values

        if not all([custom_signal_operator, custom_signal_key, target_custom_signal_values]):
            logger.warning("Missing operator, key, or target values for custom signal condition.")
            return False

        if not target_custom_signal_values:
            return False

        actual_custom_signal_value = getattr(context, custom_signal_key, None)

        if actual_custom_signal_value is None:
            logger.warning("Custom signal value not found in context: %s", custom_signal_key)
            return False
        if custom_signal_operator == CustomSignalOperator.STRING_CONTAINS:
            return compare_strings(lambda target, actual: target in actual)
        elif custom_signal_operator == CustomSignalOperator.STRING_DOES_NOT_CONTAIN:
            return not compare_strings(lambda target, actual: target in actual)
        elif custom_signal_operator == CustomSignalOperator.STRING_EXACTLY_MATCHES:
            return compare_strings(lambda target, actual: target.strip() == actual.strip())
        elif custom_signal_operator == CustomSignalOperator.STRING_CONTAINS_REGEX:
            return compare_strings(lambda target, actual: re.search(target, actual) is not None)
        elif custom_signal_operator == CustomSignalOperator.NUMERIC_LESS_THAN:
            return compare_numbers(lambda r: r < 0)
        elif custom_signal_operator == CustomSignalOperator.NUMERIC_LESS_EQUAL:
            return compare_numbers(lambda r: r <= 0)
        elif custom_signal_operator == CustomSignalOperator.NUMERIC_EQUAL:
            return compare_numbers(lambda r: r == 0)
        elif custom_signal_operator == CustomSignalOperator.NUMERIC_NOT_EQUAL:
            return compare_numbers(lambda r: r != 0)
        elif custom_signal_operator == CustomSignalOperator.NUMERIC_GREATER_THAN:
            return compare_numbers(lambda r: r > 0)
        elif custom_signal_operator == CustomSignalOperator.NUMERIC_GREATER_EQUAL:
            return compare_numbers(lambda r: r >= 0)
        elif custom_signal_operator == CustomSignalOperator.SEMANTIC_VERSION_LESS_THAN:
            return compare_semantic_versions(lambda r: r < 0)
        elif custom_signal_operator == CustomSignalOperator.SEMANTIC_VERSION_LESS_EQUAL:
            return compare_semantic_versions(lambda r: r <= 0)
        elif custom_signal_operator == CustomSignalOperator.SEMANTIC_VERSION_EQUAL:
            return compare_semantic_versions(lambda r: r == 0)
        elif custom_signal_operator == CustomSignalOperator.SEMANTIC_VERSION_NOT_EQUAL:
            return compare_semantic_versions(lambda r: r != 0)
        elif custom_signal_operator == CustomSignalOperator.SEMANTIC_VERSION_GREATER_THAN:
            return compare_semantic_versions(lambda r: r > 0)
        elif custom_signal_operator == CustomSignalOperator.SEMANTIC_VERSION_GREATER_EQUAL:
            return compare_semantic_versions(lambda r: r >= 0)

        logger.warning("Unknown custom signal operator: %s", custom_signal_operator)
        return False

        def compare_strings(predicate_fn: Callable[[str, str], bool]) -> bool:
            return any(predicate_fn(target, str(actual_custom_signal_value)) for target in target_custom_signal_values)

        def compare_numbers(predicate_fn: Callable[[int], bool]) -> bool:
            try:
                target = float(target_custom_signal_values[0])
                actual = float(actual_custom_signal_value)
                result = -1 if actual < target else 1 if actual > target else 0
                return predicate_fn(result)
            except ValueError:
                logger.warning("Invalid numeric value for comparison.")
                return False

        def compare_semantic_versions(predicate_fn: Callable[[int], bool]) -> bool:
            return compare_versions(str(actual_custom_signal_value), str(target_custom_signal_values[0]), predicate_fn)
            
        def compare_versions(version1: str, version2: str, predicate_fn: Callable[[int], bool]) -> bool:
            """
            Compares two semantic version strings.

            Args:
            version1: The first semantic version string.
            version2: The second semantic version string.
            predicate_fn: A function that takes an integer and returns a boolean.

            Returns:
            The result of the predicate function.
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
                    elif part1 > part2:
                        return predicate_fn(1)
                return predicate_fn(0) 

            except ValueError:
                logger.warning("Invalid semantic version format for comparison.")
                return False


class RemoteConfig:
    """
    Represents a Server 
    Side Remote Config Class.
    """

    def __init__(self, app=None):
        timeout = app.options.get('httpTimeout',
                                  _http_client.DEFAULT_TIMEOUT_SECONDS)
        self._credential = app.credential.get_credential()
        self._api_client = _http_client.RemoteConfigApiClient(
            credential=self._credential, timeout=timeout)

    async def get_server_template(self, default_config: Optional[Dict[str, str]] = None):
        template = self.init_server_template(default_config)
        await template.load()
        return template

    def init_server_template(self, default_config: Optional[Dict[str, str]] = None):
        template = ServerTemplate(self._api_client,
                                  default_config=default_config)
        return template

class ServerTemplateData:
    """Represents a Server Template Data class."""

    def __init__(self, template: Dict[str, Any]):
        self.conditions = template.get('conditions', [])
        self.parameters = template.get('parameters', {})
        # ... (Add any other necessary attributes from the template data) ...


class ServerTemplate:
    """Represents a Server Template with implementations for loading and evaluating the template."""

    def __init__(self, client, default_config: Optional[Dict[str, str]] = None):
        """
        Initializes a ServerTemplate instance.

        Args:
          client: The API client used to fetch the server template.
          default_config:  A dictionary of default configuration values.
        """
        self._client = client
        self._condition_evaluator = ConditionEvaluator()
        self._cache = None
        self._stringified_default_config = {key: str(value) for key, value in default_config.items()} if default_config else {}

    async def load(self):
        """Fetches and caches the server template from the Remote Config API."""
        self._cache = await self._client.get_server_template()

    def set(self, template):
        """
        Sets the server template from a string or ServerTemplateData object.

        Args:
          template: The template to set, either as a JSON string or a ServerTemplateData object.
        """
        if isinstance(template, str):
            try:
                import json
                parsed_template = json.loads(template)
                self._cache = ServerTemplateData(parsed_template)
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to parse the JSON string: {template}. {e}")
        elif isinstance(template, ServerTemplateData):
            self._cache = template
        else:
            raise TypeError("template must be a string or ServerTemplateData object")

    def evaluate(self, context: Optional[Dict[str, Union[str, int]]] = None) -> 'ServerConfig':
        """
        Evaluates the cached server template to produce a ServerConfig.

        Args:
          context: A dictionary of values to use for evaluating conditions.

        Returns:
          A ServerConfig object.
        """
        if not self._cache:
            raise ValueError("No Remote Config Server template in cache. Call load() before calling evaluate().")

        context = context or {}
        evaluated_conditions = self._condition_evaluator.evaluate_conditions(
            self._cache.conditions, EvaluationContext(**context)
        )

        config_values = {}

        for key, value in self._stringified_default_config.items():
            config_values[key] = Value('default', value)

        for key, parameter in self._cache.parameters.items():
            conditional_values = parameter.get('conditionalValues', {})
            default_value = parameter.get('defaultValue')

            parameter_value_wrapper = None
            for condition_name, condition_evaluation in evaluated_conditions.items():
                if condition_name in conditional_values and condition_evaluation:
                    parameter_value_wrapper = conditional_values[condition_name]
                    break

            if parameter_value_wrapper and parameter_value_wrapper.get('useInAppDefault'):
                logger.info("Using in-app default value for key '%s'", key)
                continue

            if parameter_value_wrapper:
                config_values[key] = Value('remote', parameter_value_wrapper.get('value'))
                continue

            if not default_value:
                logger.warning("No default value found for key '%s'", key)
                continue

            if default_value.get('useInAppDefault'):
                logger.info("Using in-app default value for key '%s'", key)
                continue

            config_values[key] = Value('remote', default_value.get('value'))

        return ServerConfig(config_values)


class ServerConfig:
    """Represents a Remote Config Server Side Config."""

    def __init__(self, config_values):
        self._config_values = config_values

    def get_boolean(self, key):
        return self._config_values[key].as_boolean()

    def get_string(self, key):
        return self._config_values[key].as_string()

    def get_int(self, key):
        return int(self._config_values[key].as_number())

    def get_value(self, key):
        return self._config_values[key]

class Value:
    """
    Represents a value fetched from Remote Config.
    """
    DEFAULT_VALUE_FOR_BOOLEAN = False
    DEFAULT_VALUE_FOR_STRING = ''
    DEFAULT_VALUE_FOR_NUMBER = 0
    BOOLEAN_TRUTHY_VALUES = ['1', 'true', 't', 'yes', 'y', 'on']

    def __init__(self, source: ValueSource, value: str = DEFAULT_VALUE_FOR_STRING):
        """
        Initializes a Value instance.

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
        return self.value.lower() in self.BOOLEAN_TRUTHY_VALUES

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
