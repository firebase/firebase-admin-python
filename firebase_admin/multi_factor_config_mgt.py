class TotpProviderConfig:
    """Represents a TOTP Provider Configuration
    """
    def __init__(self, data):
        if not isinstance(data, dict):
            raise ValueError('Invalid data argument in TotpProviderConfig constructor: {0}'.format(data))

        self._data = data
    
    @property
    def adjacent_intervals(self):
        return self._data.get('adjacentIntervals')
    
class ProviderConfig:
    """Represents a multi factor provider configuration
    """

    def __init__(self, data):
        if not isinstance(data, dict):
            raise ValueError('Invalid data argument in ProviderConfig constructor: {0}'.format(data))

        self._data = data
    @property
    def state(self):
        return self._data.get('state')

    @property
    def totp_provider_config(self):
        data = self._data.get('totpProviderConfig')
        if data:
            return TotpProviderConfig(data)
        return None

class MultiFactorConfig:
    """Represents a multi factor configuration for tenant or project
    """

    def __init__(self, data):
        print("MFA CONFIG\n", data)
        if not isinstance(data, dict):
            raise ValueError('Invalid data argument in MultiFactorConfig constructor: {0}'.format(data))

        self._data = data

    @property
    def state(self):
        return self._data.get('state')

    @property
    def enabled_providers(self):
        return self._data.get('factorIds')

    @property
    def provider_configs(self):
        data = self._data.get('providerConfigs')
        print("HERE/n", data)
        if data:
            return [ProviderConfig(d) for d in data]
        return None