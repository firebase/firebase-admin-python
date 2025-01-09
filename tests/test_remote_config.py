# Copyright 2024 Google Inc.
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

"""Tests for firebase_admin.remote_config."""
import json
import uuid
import pytest
import firebase_admin
from firebase_admin.remote_config import (
    CustomSignalOperator,
    PercentConditionOperator,
    _REMOTE_CONFIG_ATTRIBUTE,
    _RemoteConfigService)
from firebase_admin import remote_config, _utils
from tests import testutils

VERSION_INFO = {
    'versionNumber': '86',
    'updateOrigin': 'ADMIN_SDK_PYTHON',
    'updateType': 'INCREMENTAL_UPDATE',
    'updateUser': {
        'email': 'firebase-adminsdk@gserviceaccount.com'
    },
    'description': 'production version',
    'updateTime': '2024-11-05T16:45:03.541527Z'
    }

SERVER_REMOTE_CONFIG_RESPONSE = {
    'conditions': [
        {
            'name': 'ios',
            'condition': {
                'orCondition': {
                    'conditions': [
                        {
                            'andCondition': {
                                'conditions': [
                                    {'true': {}}
                                ]
                            }
                        }
                    ]
                }
            }
        },
    ],
    'parameters': {
        'holiday_promo_enabled': {
            'defaultValue': {'value': 'true'},
            'conditionalValues': {'ios': {'useInAppDefault': 'true'}}
        },
    },
    'parameterGroups': '',
    'etag': 'etag-123456789012-5',
    'version': VERSION_INFO,
    }

SEMENTIC_VERSION_LESS_THAN_TRUE = [
    CustomSignalOperator.SEMANTIC_VERSION_LESS_THAN.value, ['12.1.3.444'], '12.1.3.443', True]
SEMENTIC_VERSION_EQUAL_TRUE = [
    CustomSignalOperator.SEMANTIC_VERSION_EQUAL.value, ['12.1.3.444'], '12.1.3.444', True]
SEMANTIC_VERSION_GREATER_THAN_FALSE = [
    CustomSignalOperator.SEMANTIC_VERSION_LESS_THAN.value, ['12.1.3.4'], '12.1.3.4', False]
SEMANTIC_VERSION_INVALID_FORMAT_STRING = [
    CustomSignalOperator.SEMANTIC_VERSION_LESS_THAN.value, ['12.1.3.444'], '12.1.3.abc', False]
SEMANTIC_VERSION_INVALID_FORMAT_NEGATIVE_INTEGER = [
    CustomSignalOperator.SEMANTIC_VERSION_LESS_THAN.value, ['12.1.3.444'], '12.1.3.-2', False]

class TestEvaluate:
    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': 'project-id'})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    def test_evaluate_or_and_true_condition_true(self):
        app = firebase_admin.get_app()
        default_config = {'param1': 'in_app_default_param1', 'param3': 'in_app_default_param3'}
        condition = {
            'name': 'is_true',
            'condition': {
                'orCondition': {
                    'conditions': [
                        {
                            'andCondition': {
                                'conditions': [
                                    {
                                        'name': '',
                                        'true': {
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
        }
        template_data = {
            'conditions': [condition],
            'parameters': {
                'is_enabled': {
                    'defaultValue': {'value': 'false'},
                    'conditionalValues': {'is_true': {'value': 'true'}}
                },
            },
            'parameterGroups': '',
            'version': '',
            'etag': 'etag'
        }
        server_template = remote_config.init_server_template(
            app=app,
            default_config=default_config,
            template_data_json=json.dumps(template_data)
        )

        server_config = server_template.evaluate()
        assert server_config.get_boolean('is_enabled')

    def test_evaluate_or_and_false_condition_false(self):
        app = firebase_admin.get_app()
        default_config = {'param1': 'in_app_default_param1', 'param3': 'in_app_default_param3'}
        condition = {
            'name': 'is_true',
            'condition': {
                'orCondition': {
                    'conditions': [
                        {
                            'andCondition': {
                                'conditions': [
                                    {
                                        'name': '',
                                        'false': {
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
        }
        template_data = {
            'conditions': [condition],
            'parameters': {
                'is_enabled': {
                    'defaultValue': {'value': 'false'},
                    'conditionalValues': {'is_true': {'value': 'true'}}
                },
            },
            'parameterGroups': '',
            'version': '',
            'etag': 'etag'
        }
        server_template = remote_config.init_server_template(
            app=app,
            default_config=default_config,
            template_data_json=json.dumps(template_data)
        )

        server_config = server_template.evaluate()
        assert not server_config.get_boolean('is_enabled')

    def test_evaluate_non_or_condition(self):
        app = firebase_admin.get_app()
        default_config = {'param1': 'in_app_default_param1', 'param3': 'in_app_default_param3'}
        condition = {
            'name': 'is_true',
            'condition': {
                'true': {
                }
            }
        }
        template_data = {
            'conditions': [condition],
            'parameters': {
                'is_enabled': {
                    'defaultValue': {'value': 'false'},
                    'conditionalValues': {'is_true': {'value': 'true'}}
                },
            },
            'parameterGroups': '',
            'version': '',
            'etag': 'etag'
        }
        server_template = remote_config.init_server_template(
            app=app,
            default_config=default_config,
            template_data_json=json.dumps(template_data)
        )

        server_config = server_template.evaluate()
        assert server_config.get_boolean('is_enabled')

    def test_evaluate_return_conditional_values_honor_order(self):
        app = firebase_admin.get_app()
        default_config = {'param1': 'in_app_default_param1', 'param3': 'in_app_default_param3'}
        template_data = {
            'conditions': [
                {
                    'name': 'is_true',
                    'condition': {
                        'orCondition': {
                            'conditions': [
                                {
                                    'andCondition': {
                                        'conditions': [
                                            {
                                                'true': {
                                                }
                                            }
                                        ]
                                    }
                                }
                            ]
                        }
                    }
                },
                {
                    'name': 'is_true_too',
                    'condition': {
                        'orCondition': {
                            'conditions': [
                                {
                                    'andCondition': {
                                        'conditions': [
                                            {
                                                'true': {
                                                }
                                            }
                                        ]
                                    }
                                }
                            ]
                        }
                    }
                }
            ],
            'parameters': {
                'dog_type': {
                    'defaultValue': {'value': 'chihuahua'},
                    'conditionalValues': {
                        'is_true_too': {'value': 'dachshund'},
                        'is_true': {'value': 'corgi'}
                    }
                },
            },
            'parameterGroups':'',
            'version':'',
            'etag': 'etag'
        }
        server_template = remote_config.init_server_template(
            app=app,
            default_config=default_config,
            template_data_json=json.dumps(template_data)
        )
        server_config = server_template.evaluate()
        assert server_config.get_string('dog_type') == 'corgi'

    def test_evaluate_default_when_no_param(self):
        app = firebase_admin.get_app()
        default_config = {'promo_enabled': False, 'promo_discount': '20',}
        template_data = SERVER_REMOTE_CONFIG_RESPONSE
        template_data['parameters'] = {}
        server_template = remote_config.init_server_template(
            app=app,
            default_config=default_config,
            template_data_json=json.dumps(template_data)
        )
        server_config = server_template.evaluate()
        assert server_config.get_boolean('promo_enabled') == default_config.get('promo_enabled')
        assert server_config.get_int('promo_discount') == int(default_config.get('promo_discount'))

    def test_evaluate_default_when_no_default_value(self):
        app = firebase_admin.get_app()
        default_config = {'default_value': 'local default'}
        template_data = SERVER_REMOTE_CONFIG_RESPONSE
        template_data['parameters'] = {
            'default_value': {}
        }
        server_template = remote_config.init_server_template(
            app=app,
            default_config=default_config,
            template_data_json=json.dumps(template_data)
        )
        server_config = server_template.evaluate()
        assert server_config.get_string('default_value') == default_config.get('default_value')

    def test_evaluate_default_when_in_default(self):
        app = firebase_admin.get_app()
        template_data = SERVER_REMOTE_CONFIG_RESPONSE
        template_data['parameters'] = {
            'remote_default_value': {}
        }
        default_config = {
            'inapp_default': '🐕'
        }
        server_template = remote_config.init_server_template(
            app=app,
            default_config=default_config,
            template_data_json=json.dumps(template_data)
        )
        server_config = server_template.evaluate()
        assert server_config.get_string('inapp_default') == default_config.get('inapp_default')

    def test_evaluate_default_when_defined(self):
        app = firebase_admin.get_app()
        template_data = SERVER_REMOTE_CONFIG_RESPONSE
        template_data['parameters'] = {}
        default_config = {
            'dog_type': 'shiba'
        }
        server_template = remote_config.init_server_template(
            app=app,
            default_config=default_config,
            template_data_json=json.dumps(template_data)
        )
        server_config = server_template.evaluate()
        assert server_config.get_string('dog_type') == 'shiba'

    def test_evaluate_return_numeric_value(self):
        app = firebase_admin.get_app()
        template_data = SERVER_REMOTE_CONFIG_RESPONSE
        default_config = {
            'dog_age': '12'
        }
        server_template = remote_config.init_server_template(
            app=app,
            default_config=default_config,
            template_data_json=json.dumps(template_data)
        )
        server_config = server_template.evaluate()
        assert server_config.get_int('dog_age') == int(default_config.get('dog_age'))

    def test_evaluate_return_boolean_value(self):
        app = firebase_admin.get_app()
        template_data = SERVER_REMOTE_CONFIG_RESPONSE
        default_config = {
            'dog_is_cute': True
        }
        server_template = remote_config.init_server_template(
            app=app,
            default_config=default_config,
            template_data_json=json.dumps(template_data)
        )
        server_config = server_template.evaluate()
        assert server_config.get_boolean('dog_is_cute')

    def test_evaluate_unknown_operator_to_false(self):
        app = firebase_admin.get_app()
        condition = {
            'name': 'is_true',
            'condition': {
                'orCondition': {
                    'conditions': [{
                        'andCondition': {
                            'conditions': [{
                                'percent': {
                                    'percentOperator': PercentConditionOperator.UNKNOWN.value
                                }
                            }],
                        }
                    }]
                }
            }
        }
        default_config = {
            'dog_is_cute': True
        }
        template_data = {
            'conditions': [condition],
            'parameters': {
                'is_enabled': {
                    'defaultValue': {'value': 'false'},
                    'conditionalValues': {'is_true': {'value': 'true'}}
                },
            },
            'parameterGroups':'',
            'version':'',
            'etag': '123'
        }
        context = {'randomization_id': '123'}
        server_template = remote_config.init_server_template(
            app=app,
            default_config=default_config,
            template_data_json=json.dumps(template_data)
        )
        server_config = server_template.evaluate(context)
        assert not server_config.get_boolean('is_enabled')

    def test_evaluate_less_or_equal_to_max_to_true(self):
        app = firebase_admin.get_app()
        condition = {
            'name': 'is_true',
            'condition': {
                'orCondition': {
                    'conditions': [{
                        'andCondition': {
                            'conditions': [{
                                'percent': {
                                    'percentOperator': PercentConditionOperator.LESS_OR_EQUAL.value,
                                    'seed': 'abcdef',
                                    'microPercent': 100_000_000
                                }
                            }],
                        }
                    }]
                }
            }
        }
        default_config = {
            'dog_is_cute': True
        }
        template_data = {
            'conditions': [condition],
            'parameters': {
                'is_enabled': {
                    'defaultValue': {'value': 'false'},
                    'conditionalValues': {'is_true': {'value': 'true'}}
                },
            },
            'parameterGroups':'',
            'version':'',
            'etag': '123'
        }
        context = {'randomization_id': '123'}
        server_template = remote_config.init_server_template(
            app=app,
            default_config=default_config,
            template_data_json=json.dumps(template_data)
        )
        server_config = server_template.evaluate(context)
        assert server_config.get_boolean('is_enabled')

    def test_evaluate_undefined_micropercent_to_false(self):
        app = firebase_admin.get_app()
        condition = {
            'name': 'is_true',
            'condition': {
                'orCondition': {
                    'conditions': [{
                        'andCondition': {
                            'conditions': [{
                                'percent': {
                                    'percentOperator': PercentConditionOperator.LESS_OR_EQUAL.value,
                                    # Leaves microPercent undefined
                                }
                            }],
                        }
                    }]
                }
            }
        }
        default_config = {
            'dog_is_cute': True
        }
        template_data = {
            'conditions': [condition],
            'parameters': {
                'is_enabled': {
                    'defaultValue': {'value': 'false'},
                    'conditionalValues': {'is_true': {'value': 'true'}}
                },
            },
            'parameterGroups':'',
            'version':'',
            'etag': '123'
        }
        context = {'randomization_id': '123'}
        server_template = remote_config.init_server_template(
            app=app,
            default_config=default_config,
            template_data_json=json.dumps(template_data)
        )
        server_config = server_template.evaluate(context)
        assert not server_config.get_boolean('is_enabled')

    def test_evaluate_undefined_micropercentrange_to_false(self):
        app = firebase_admin.get_app()
        condition = {
            'name': 'is_true',
            'condition': {
                'orCondition': {
                    'conditions': [{
                        'andCondition': {
                            'conditions': [{
                                'percent': {
                                    'percentOperator': PercentConditionOperator.BETWEEN.value,
                                    # Leaves microPercent undefined
                                }
                            }],
                        }
                    }]
                }
            }
        }
        default_config = {
            'dog_is_cute': True
        }
        template_data = {
            'conditions': [condition],
            'parameters': {
                'is_enabled': {
                    'defaultValue': {'value': 'false'},
                    'conditionalValues': {'is_true': {'value': 'true'}}
                },
            },
            'parameterGroups':'',
            'version':'',
            'etag': '123'
        }
        context = {'randomization_id': '123'}
        server_template = remote_config.init_server_template(
            app=app,
            default_config=default_config,
            template_data_json=json.dumps(template_data)
        )
        server_config = server_template.evaluate(context)
        assert not server_config.get_boolean('is_enabled')

    def test_evaluate_between_min_max_to_true(self):
        app = firebase_admin.get_app()
        condition = {
            'name': 'is_true',
            'condition': {
                'orCondition': {
                    'conditions': [{
                        'andCondition': {
                            'conditions': [{
                                'percent': {
                                    'percentOperator': PercentConditionOperator.BETWEEN.value,
                                    'seed': 'abcdef',
                                    'microPercentRange': {
                                        'microPercentLowerBound': 0,
                                        'microPercentUpperBound': 100_000_000
                                    }
                                }
                            }],
                        }
                    }]
                }
            }
        }
        default_config = {
            'dog_is_cute': True
        }
        template_data = {
            'conditions': [condition],
            'parameters': {
                'is_enabled': {
                    'defaultValue': {'value': 'false'},
                    'conditionalValues': {'is_true': {'value': 'true'}}
                },
            },
            'parameterGroups':'',
            'version':'',
            'etag': '123'
        }
        context = {'randomization_id': '123'}
        server_template = remote_config.init_server_template(
            app=app,
            default_config=default_config,
            template_data_json=json.dumps(template_data)
        )
        server_config = server_template.evaluate(context)
        assert server_config.get_boolean('is_enabled')

    def test_evaluate_between_equal_bounds_to_false(self):
        app = firebase_admin.get_app()
        condition = {
            'name': 'is_true',
            'condition': {
                'orCondition': {
                    'conditions': [{
                        'andCondition': {
                            'conditions': [{
                                'percent': {
                                    'percentOperator': PercentConditionOperator.BETWEEN.value,
                                    'seed': 'abcdef',
                                    'microPercentRange': {
                                        'microPercentLowerBound': 50000000,
                                        'microPercentUpperBound': 50000000
                                    }
                                }
                            }],
                        }
                    }]
                }
            }
        }
        default_config = {
            'dog_is_cute': True
        }
        template_data = {
            'conditions': [condition],
            'parameters': {
                'is_enabled': {
                    'defaultValue': {'value': 'false'},
                    'conditionalValues': {'is_true': {'value': 'true'}}
                },
            },
            'parameterGroups':'',
            'version':'',
            'etag': '123'
        }
        context = {'randomization_id': '123'}
        server_template = remote_config.init_server_template(
            app=app,
            default_config=default_config,
            template_data_json=json.dumps(template_data)
        )
        server_config = server_template.evaluate(context)
        assert not server_config.get_boolean('is_enabled')

    def test_evaluate_less_or_equal_to_approx(self):
        app = firebase_admin.get_app()
        condition = {
            'name': 'is_true',
            'condition': {
                'orCondition': {
                    'conditions': [{
                        'andCondition': {
                            'conditions': [{
                                'percent': {
                                    'percentOperator': PercentConditionOperator.LESS_OR_EQUAL.value,
                                    'seed': 'abcdef',
                                    'microPercent': 10_000_000 # 10%
                                }
                            }],
                        }
                    }]
                }
            }
        }
        default_config = {
            'dog_is_cute': True
        }

        truthy_assignments = self.evaluate_random_assignments(condition, 100000,
                                                              app, default_config)
        tolerance = 284
        assert truthy_assignments >= 10000 - tolerance
        assert truthy_assignments <= 10000 + tolerance

    def test_evaluate_between_approx(self):
        app = firebase_admin.get_app()
        condition = {
            'name': 'is_true',
            'condition': {
                'orCondition': {
                    'conditions': [{
                        'andCondition': {
                            'conditions': [{
                                'percent': {
                                    'percentOperator': PercentConditionOperator.BETWEEN.value,
                                    'seed': 'abcdef',
                                    'microPercentRange': {
                                        'microPercentLowerBound': 40_000_000,
                                        'microPercentUpperBound': 60_000_000
                                    }
                                }
                            }],
                        }
                    }]
                }
            }
        }
        default_config = {
            'dog_is_cute': True
        }

        truthy_assignments = self.evaluate_random_assignments(condition, 100000,
                                                              app, default_config)
        tolerance = 379
        assert truthy_assignments >= 20000 - tolerance
        assert truthy_assignments <= 20000 + tolerance

    def test_evaluate_between_interquartile_range_accuracy(self):
        app = firebase_admin.get_app()
        condition = {
            'name': 'is_true',
            'condition': {
                'orCondition': {
                    'conditions': [{
                        'andCondition': {
                            'conditions': [{
                                'percent': {
                                    'percentOperator': PercentConditionOperator.BETWEEN.value,
                                    'seed': 'abcdef',
                                    'microPercentRange': {
                                        'microPercentLowerBound': 25_000_000,
                                        'microPercentUpperBound': 75_000_000
                                    }
                                }
                            }],
                        }
                    }]
                }
            }
        }
        default_config = {
            'dog_is_cute': True
        }

        truthy_assignments = self.evaluate_random_assignments(condition, 100000,
                                                              app, default_config)
        tolerance = 490
        assert truthy_assignments >= 50000 - tolerance
        assert truthy_assignments <= 50000 + tolerance

    def evaluate_random_assignments(self, condition, num_of_assignments, mock_app, default_config):
        """Evaluates random assignments based on a condition.

        Args:
        condition: The condition to evaluate.
        num_of_assignments: The number of assignments to generate.
        condition_evaluator: An instance of the ConditionEvaluator class.

        Returns:
            int: The number of assignments that evaluated to true.
        """
        eval_true_count = 0
        template_data = {
            'conditions': [condition],
            'parameters': {
                'is_enabled': {
                    'defaultValue': {'value': 'false'},
                    'conditionalValues': {'is_true': {'value': 'true'}}
                },
            },
            'parameterGroups':'',
            'version':'',
            'etag': '123'
        }
        server_template = remote_config.init_server_template(
            app=mock_app,
            default_config=default_config,
            template_data_json=json.dumps(template_data)
        )

        for _ in range(num_of_assignments):
            context = {'randomization_id': str(uuid.uuid4())}
            result = server_template.evaluate(context)
            if result.get_boolean('is_enabled') is True:
                eval_true_count += 1

        return eval_true_count

    @pytest.mark.parametrize(
        'custom_signal_opearator, \
            target_custom_signal_value, actual_custom_signal_value, parameter_value',
        [
            SEMENTIC_VERSION_LESS_THAN_TRUE,
            SEMANTIC_VERSION_GREATER_THAN_FALSE,
            SEMENTIC_VERSION_EQUAL_TRUE,
            SEMANTIC_VERSION_INVALID_FORMAT_NEGATIVE_INTEGER,
            SEMANTIC_VERSION_INVALID_FORMAT_STRING
        ])
    def test_evaluate_custom_signal_semantic_version(self,
                                                     custom_signal_opearator,
                                                     target_custom_signal_value,
                                                     actual_custom_signal_value,
                                                     parameter_value):
        app = firebase_admin.get_app()
        condition = {
            'name': 'is_true',
            'condition': {
                'orCondition': {
                    'conditions': [{
                        'andCondition': {
                            'conditions': [{
                                'customSignal': {
                                    'customSignalOperator': custom_signal_opearator,
                                    'customSignalKey': 'sementic_version_key',
                                    'targetCustomSignalValues': target_custom_signal_value
                                }
                            }],
                        }
                    }]
                }
            }
        }
        default_config = {
            'dog_is_cute': True
        }
        template_data = {
            'conditions': [condition],
            'parameters': {
                'is_enabled': {
                    'defaultValue': {'value': 'false'},
                    'conditionalValues': {'is_true': {'value': 'true'}}
                },
            },
            'parameterGroups':'',
            'version':'',
            'etag': '123'
        }
        context = {'randomization_id': '123', 'sementic_version_key': actual_custom_signal_value}
        server_template = remote_config.init_server_template(
            app=app,
            default_config=default_config,
            template_data_json=json.dumps(template_data)
        )
        server_config = server_template.evaluate(context)
        assert server_config.get_boolean('is_enabled') == parameter_value


class MockAdapter(testutils.MockAdapter):
    """A Mock HTTP Adapter that provides Firebase Remote Config responses with ETag in header."""

    ETAG = 'etag'

    def __init__(self, data, status, recorder, etag=ETAG):
        testutils.MockAdapter.__init__(self, data, status, recorder)
        self._etag = etag

    def send(self, request, **kwargs):
        resp = super(MockAdapter, self).send(request, **kwargs)
        resp.headers = {'etag': self._etag}
        return resp


class TestRemoteConfigService:
    """Tests methods on _RemoteConfigService"""
    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': 'project-id'})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    @pytest.mark.asyncio
    async def test_rc_instance_get_server_template(self):
        recorder = []
        response = json.dumps({
            'parameters': {
                'test_key': 'test_value'
            },
            'conditions': [],
            'version': 'test'
            })

        rc_instance = _utils.get_app_service(firebase_admin.get_app(),
                                             _REMOTE_CONFIG_ATTRIBUTE, _RemoteConfigService)
        rc_instance._client.session.mount(
            'https://firebaseremoteconfig.googleapis.com',
            MockAdapter(response, 200, recorder))

        template = await rc_instance.get_server_template()

        assert template.parameters == dict(test_key="test_value")
        assert str(template.version) == 'test'
        assert str(template.etag) == 'etag'

    @pytest.mark.asyncio
    async def test_rc_instance_get_server_template_empty_params(self):
        recorder = []
        response = json.dumps({
            'conditions': [],
            'version': 'test'
            })

        rc_instance = _utils.get_app_service(firebase_admin.get_app(),
                                             _REMOTE_CONFIG_ATTRIBUTE, _RemoteConfigService)
        rc_instance._client.session.mount(
            'https://firebaseremoteconfig.googleapis.com',
            MockAdapter(response, 200, recorder))

        template = await rc_instance.get_server_template()

        assert template.parameters == {}
        assert str(template.version) == 'test'
        assert str(template.etag) == 'etag'


class TestRemoteConfigModule:
    """Tests methods on firebase_admin.remote_config"""
    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': 'project-id'})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    def test_init_server_template(self):
        app = firebase_admin.get_app()
        template_data = {
            'conditions': [],
            'parameters': {
                'test_key': {
                    'defaultValue': {'value': 'test_value'},
                    'conditionalValues': {}
                }
            },
            'version': '',
        }

        template = remote_config.init_server_template(
            app=app,
            default_config={'default_test': 'default_value'},
            template_data_json=json.dumps(template_data)
        )

        config = template.evaluate()
        assert config.get_string('test_key') == 'test_value'

    @pytest.mark.asyncio
    async def test_get_server_template(self):
        app = firebase_admin.get_app()
        rc_instance = _utils.get_app_service(app,
                                             _REMOTE_CONFIG_ATTRIBUTE, _RemoteConfigService)

        recorder = []
        response = json.dumps({
            'parameters': {
                'test_key': {
                    'defaultValue': {'value': 'test_value'},
                    'conditionalValues': {}
                }
            },
            'conditions': [],
            'version': 'test'
            })

        rc_instance._client.session.mount(
            'https://firebaseremoteconfig.googleapis.com',
            MockAdapter(response, 200, recorder))

        template = await remote_config.get_server_template(app=app)

        config = template.evaluate()
        assert config.get_string('test_key') == 'test_value'

    @pytest.mark.asyncio
    async def test_server_template_to_json(self):
        app = firebase_admin.get_app()
        rc_instance = _utils.get_app_service(app,
                                             _REMOTE_CONFIG_ATTRIBUTE, _RemoteConfigService)

        recorder = []
        response = json.dumps({
            'parameters': {
                'test_key': {
                    'defaultValue': {'value': 'test_value'},
                    'conditionalValues': {}
                }
            },
            'conditions': [],
            'version': 'test'
            })

        expected_template_json = '{"parameters": {' \
            '"test_key": {' \
                '"defaultValue": {' \
                    '"value": "test_value"}, ' \
                    '"conditionalValues": {}}}, "conditions": [], ' \
                    '"version": "test", "etag": "etag"}'

        rc_instance._client.session.mount(
            'https://firebaseremoteconfig.googleapis.com',
            MockAdapter(response, 200, recorder))
        template = await remote_config.get_server_template(app=app)

        template_json = template.to_json()
        assert template_json == expected_template_json
