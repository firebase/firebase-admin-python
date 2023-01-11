from firebase_admin import project_config_mgt
import pytest

class TestProject:

    mfa_config = {
        'state':'ENABLED',
        'factorIds':['PHONE_SMS'],
        'providerConfigs': [
            {
                'state':'ENABLED',
                'totpProviderConfig': {
                    'adjacentIntervals':5
                }
            }
        ]
    }
    def test_update_project(self, mfa=mfa_config):
        project = project_config_mgt.update_project(mfa=mfa)
        assert isinstance(project, project_config_mgt.Project)
        assert project.mfa.state == 'ENABLED'
        assert project.mfa.enabled_providers == ['PHONE_SMS']
        assert project.mfa.provider_configs[0].state == 'ENABLED'
        assert project.mfa.provider_configs[0].totp_provider_config.adjacent_intervals == 5

    def test_get_project(self):
        project = project_config_mgt.get_project()
        assert isinstance(project, project_config_mgt.Project)
        assert project.mfa.state == 'ENABLED'
        assert project.mfa.enabled_providers == ['PHONE_SMS']
        assert project.mfa.provider_configs[0].state == 'ENABLED'
        assert project.mfa.provider_configs[0].totp_provider_config.adjacent_intervals == 5


