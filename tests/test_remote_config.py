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

"""Tests for firebase_admin.remote_config."""
import json
import uuid
import firebase_admin
from firebase_admin.remote_config import (
    _REMOTE_CONFIG_ATTRIBUTE,
    _RemoteConfigService,
    PercentConditionOperator)
from firebase_admin import remote_config, _utils
from tests import testutils


VERSION_INFO = {
    'versionNumber': '86',
    'updateOrigin': 'ADMIN_SDK_NODE',
    'updateType': 'INCREMENTAL_UPDATE',
    'updateUser': {
        'email': 'firebase-adminsdk@gserviceaccount.com'
    },
    'description': 'production version',
    'updateTime': '2020-06-15T16:45:03.541527Z'
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

class MockAdapter(testutils.MockAdapter):
    """A Mock HTTP Adapter that Firebase Remote Config with ETag in header."""

    ETAG = '0'

    def __init__(self, data, status, recorder, etag=ETAG):
        testutils.MockAdapter.__init__(self, data, status, recorder)
        self._etag = etag

    def send(self, request, **kwargs):
        resp = super(MockAdapter, self).send(request, **kwargs)
        resp.headers = {'ETag': self._etag}
        return resp


class TestGetServerTemplate:
    _DEFAULT_APP = firebase_admin.initialize_app(testutils.MockCredential(), name='no_project_id')
    _RC_INSTANCE = _utils.get_app_service(_DEFAULT_APP,
                                          _REMOTE_CONFIG_ATTRIBUTE, _RemoteConfigService)
    _DEFAULT_RESPONSE = json.dumps({
        'parameters': {
            'test_key': 'test_value'
        },
        'conditions': {},
        'parameterGroups': {},
        'version': 'test'
        })

    def test_rc_instance_get_server_template(self):
        recorder = []
        self._RC_INSTANCE._client.session.mount(
            'https://firebaseremoteconfig.googleapis.com',
            MockAdapter(self._DEFAULT_RESPONSE, 200, recorder))

        template = self._RC_INSTANCE.get_server_template()

        assert template.parameters == dict(test_key="test_value")
        assert str(template.version) == 'test'

    def test_rc_instance_return_conditional_values(self):
        recorder = []
        self._RC_INSTANCE._client.session.mount(
            'https://firebaseremoteconfig.googleapis.com',
            MockAdapter(self._DEFAULT_RESPONSE, 200, recorder))
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
            'etag': '123'
        }
        server_template = remote_config.ServerTemplate(self._DEFAULT_APP, default_config)
        server_template.set(remote_config.ServerTemplateData('etag', template_data))
        server_config = server_template.evaluate()
        assert server_config.get_boolean('is_enabled')

    def test_rc_instance_return_conditional_values_true(self):
        recorder = []
        self._RC_INSTANCE._client.session.mount(
            'https://firebaseremoteconfig.googleapis.com',
            MockAdapter(self._DEFAULT_RESPONSE, 200, recorder))
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
            'etag': '123'
        }
        server_template = remote_config.ServerTemplate(self._DEFAULT_APP, default_config)
        server_template.set(remote_config.ServerTemplateData('etag', template_data))
        server_config = server_template.evaluate()
        assert server_config.get_boolean('is_enabled')

    def test_rc_instance_return_conditional_values_honor_order(self):
        recorder = []
        self._RC_INSTANCE._client.session.mount(
            'https://firebaseremoteconfig.googleapis.com',
            MockAdapter(self._DEFAULT_RESPONSE, 200, recorder))
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
            'etag': '123'
        }
        server_template = remote_config.ServerTemplate(self._DEFAULT_APP, default_config)
        server_template.set(remote_config.ServerTemplateData('etag', template_data))
        server_config = server_template.evaluate()
        assert server_config.get_string('dog_type') == 'corgi'

    def test_rc_instance_return_conditional_values_honor_order_final(self):
        recorder = []
        self._RC_INSTANCE._client.session.mount(
            'https://firebaseremoteconfig.googleapis.com',
            MockAdapter(self._DEFAULT_RESPONSE, 200, recorder))
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
            'etag': '123'
        }
        server_template = remote_config.ServerTemplate(self._DEFAULT_APP, default_config)
        server_template.set(remote_config.ServerTemplateData('etag', template_data))
        server_config = server_template.evaluate()
        assert server_config.get_string('dog_type') == 'corgi'

    def test_rc_instance_evaluate_default_when_no_param(self):
        recorder = []
        self._RC_INSTANCE._client.session.mount(
            'https://firebaseremoteconfig.googleapis.com',
            MockAdapter(self._DEFAULT_RESPONSE, 200, recorder))
        default_config = {'promo_enabled': False, 'promo_discount': 20,}
        template_data = SERVER_REMOTE_CONFIG_RESPONSE
        template_data['parameters'] = {}
        server_template = remote_config.ServerTemplate(self._DEFAULT_APP, default_config)
        server_template.set(remote_config.ServerTemplateData('etag', template_data))
        server_config = server_template.evaluate()
        assert server_config.get_boolean('promo_enabled') == default_config.get('promo_enabled')
        assert server_config.get_int('promo_discount') == default_config.get('promo_discount')

    def test_rc_instance_evaluate_default_when_no_default_value(self):
        recorder = []
        self._RC_INSTANCE._client.session.mount(
            'https://firebaseremoteconfig.googleapis.com',
            MockAdapter(self._DEFAULT_RESPONSE, 200, recorder))
        default_config = {'default_value': 'local default'}
        template_data = SERVER_REMOTE_CONFIG_RESPONSE
        template_data['parameters'] = {
            'default_value': {}
        }
        server_template = remote_config.ServerTemplate(self._DEFAULT_APP, default_config)
        server_template.set(remote_config.ServerTemplateData('etag', template_data))
        server_config = server_template.evaluate()
        assert server_config.get_string('default_value') == default_config.get('default_value')

    def test_rc_instance_evaluate_default_when_in_default(self):
        template_data = SERVER_REMOTE_CONFIG_RESPONSE
        template_data['parameters'] = {
            'remote_default_value': {}
        }
        default_config = {
            'inapp_default': '🐕'
        }
        server_template = remote_config.ServerTemplate(self._DEFAULT_APP, default_config)
        server_template.set(remote_config.ServerTemplateData('etag', template_data))
        server_config = server_template.evaluate()
        assert server_config.get_string('inapp_default') == default_config.get('inapp_default')

    def test_rc_instance_evaluate_default_when_defined(self):
        template_data = SERVER_REMOTE_CONFIG_RESPONSE
        template_data['parameters'] = {}
        default_config = {
            'dog_type': 'shiba'
        }
        server_template = remote_config.ServerTemplate(self._DEFAULT_APP, default_config)
        server_template.set(remote_config.ServerTemplateData('etag', template_data))
        server_config = server_template.evaluate()
        assert server_config.get_value('dog_type').as_string() == 'shiba'
        assert server_config.get_value('dog_type').get_source() == 'default'

    def test_rc_instance_evaluate_return_numeric_value(self):
        template_data = SERVER_REMOTE_CONFIG_RESPONSE
        default_config = {
            'dog_age': 12
        }
        server_template = remote_config.ServerTemplate(self._DEFAULT_APP, default_config)
        server_template.set(remote_config.ServerTemplateData('etag', template_data))
        server_config = server_template.evaluate()
        assert server_config.get_int('dog_age') == 12

    def test_rc_instance_evaluate_return__value(self):
        template_data = SERVER_REMOTE_CONFIG_RESPONSE
        default_config = {
            'dog_is_cute': True
        }
        server_template = remote_config.ServerTemplate(self._DEFAULT_APP, default_config)
        server_template.set(remote_config.ServerTemplateData('etag', template_data))
        server_config = server_template.evaluate()
        assert server_config.get_int('dog_is_cute')

    def test_rc_instance_evaluate_unknown_operator_false(self):
        condition = {
            'name': 'is_true',
            'condition': {
                'orCondition': {
                    'conditions': [{
                        'andCondition': {
                            'conditions': [{
                                'percent': {
                                    'percentOperator': PercentConditionOperator.UNKNOWN
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
        server_template = remote_config.ServerTemplate(self._DEFAULT_APP, default_config)
        server_template.set(remote_config.ServerTemplateData('etag', template_data))
        server_config = server_template.evaluate(context)
        assert not server_config.get_boolean('is_enabled')

    def test_rc_instance_evaluate_less_max_equal_true(self):
        condition = {
            'name': 'is_true',
            'condition': {
                'orCondition': {
                    'conditions': [{
                        'andCondition': {
                            'conditions': [{
                                'percent': {
                                    'percentOperator': PercentConditionOperator.LESS_OR_EQUAL,
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
        server_template = remote_config.ServerTemplate(self._DEFAULT_APP, default_config)
        server_template.set(remote_config.ServerTemplateData('etag', template_data))
        server_config = server_template.evaluate(context)
        assert server_config.get_boolean('is_enabled')

    def test_rc_instance_evaluate_min_max_equal_true(self):
        condition = {
            'name': 'is_true',
            'condition': {
                'orCondition': {
                    'conditions': [{
                        'andCondition': {
                            'conditions': [{
                                'percent': {
                                    'percentOperator': PercentConditionOperator.BETWEEN,
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
        server_template = remote_config.ServerTemplate(self._DEFAULT_APP, default_config)
        server_template.set(remote_config.ServerTemplateData('etag', template_data))
        server_config = server_template.evaluate(context)
        assert server_config.get_boolean('is_enabled')

    def test_rc_instance_evaluate_min_max_equal_false(self):
        condition = {
            'name': 'is_true',
            'condition': {
                'orCondition': {
                    'conditions': [{
                        'andCondition': {
                            'conditions': [{
                                'percent': {
                                    'percentOperator': PercentConditionOperator.BETWEEN,
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
        server_template = remote_config.ServerTemplate(self._DEFAULT_APP, default_config)
        server_template.set(remote_config.ServerTemplateData('etag', template_data))
        server_config = server_template.evaluate(context)
        assert not server_config.get_boolean('is_enabled')

    def test_rc_instance_evaluate_less_or_equal_approx(self):
        condition = {
            'name': 'is_true',
            'condition': {
                'orCondition': {
                    'conditions': [{
                        'andCondition': {
                            'conditions': [{
                                'percent': {
                                    'percentOperator': PercentConditionOperator.LESS_OR_EQUAL,
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

        server_template = remote_config.ServerTemplate(self._DEFAULT_APP, default_config)
        truthy_assignments = self.evaluate_random_assignments(condition, 100000, server_template)
        tolerance = 284
        assert truthy_assignments >= 10000 - tolerance
        assert truthy_assignments <= 10000 + tolerance

    def test_rc_instance_evaluate_between_approx(self):
        condition = {
            'name': 'is_true',
            'condition': {
                'orCondition': {
                    'conditions': [{
                        'andCondition': {
                            'conditions': [{
                                'percent': {
                                    'percentOperator': PercentConditionOperator.BETWEEN,
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

        server_template = remote_config.ServerTemplate(self._DEFAULT_APP, default_config)
        truthy_assignments = self.evaluate_random_assignments(condition, 100000, server_template)
        tolerance = 379
        assert truthy_assignments >= 20000 - tolerance
        assert truthy_assignments <= 20000 + tolerance

    def test_rc_instance_evaluate_between_interquartile_range_approx(self):
        condition = {
            'name': 'is_true',
            'condition': {
                'orCondition': {
                    'conditions': [{
                        'andCondition': {
                            'conditions': [{
                                'percent': {
                                    'percentOperator': PercentConditionOperator.BETWEEN,
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

        server_template = remote_config.ServerTemplate(self._DEFAULT_APP, default_config)
        truthy_assignments = self.evaluate_random_assignments(condition, 100000, server_template)
        tolerance = 474
        assert truthy_assignments >= 50000 - tolerance
        assert truthy_assignments <= 50000 + tolerance

    def evaluate_random_assignments(self, condition, num_of_assignments, server_template) -> int:
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
        server_template.set(remote_config.ServerTemplateData('etag', template_data))
        for _ in range(num_of_assignments):
            context = {'randomization_id': str(uuid.uuid4())}
            result = server_template.evaluate(context)
            if result.get_boolean('is_enabled') is True:
                eval_true_count += 1

        return eval_true_count
