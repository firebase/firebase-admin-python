import pytest

import firebase_admin
from firebase_admin import _utils
from firebase_admin import dataconnect
from firebase_admin import credentials
from tests import testutils
from unittest import mock

BASE_CONFIG = dataconnect.ConnectorConfig(
    service_id="starterproject",
    location="us-east4",
    connector="my_connector",
)

class TestConnectorConfig:
  def teardown_method(self, method):
    del method
    testutils.cleanup_apps()

  def test_connector_config_initialization(self):
    assert BASE_CONFIG.service_id == "starterproject"
    assert BASE_CONFIG.location == "us-east4"
    assert BASE_CONFIG.connector == "my_connector"
  
  def test_connector_config_is_frozen(self):
    with pytest.raises(AttributeError, match="cannot assign to field 'service_id'"):
      BASE_CONFIG.service_id = "changed_id"
    with pytest.raises(AttributeError, match="cannot assign to field 'location'"):
      BASE_CONFIG.location = "us-central1"
    with pytest.raises(AttributeError, match="cannot assign to field 'connector'"):
      BASE_CONFIG.connector = "changed_connector"

  def test_connector_config_string_written(self):
    repr_str = repr(BASE_CONFIG)
    assert "service_id='starterproject'" in repr_str
    assert "location='us-east4'" in repr_str
    assert "connector='my_connector'" in repr_str

  def test_connector_config_empty_strings(self):
    with pytest.raises(ValueError, match="service_id cannot be empty"):
      dataconnect.ConnectorConfig(service_id="", location="us-east4", connector="my_connector")

    with pytest.raises(ValueError, match="location cannot be empty"):
      dataconnect.ConnectorConfig(service_id="starterproject", location="", connector="my_connector")

    with pytest.raises(ValueError, match="connector cannot be empty"):
      dataconnect.ConnectorConfig(service_id="starterproject", location="us-east4", connector="")

  def test_connector_config_invalid_types(self):
    with pytest.raises(ValueError, match="service_id must be a string"):
      dataconnect.ConnectorConfig(service_id=None, location="us-east4", connector="my_connector")
    with pytest.raises(ValueError, match="location must be a string"):
      dataconnect.ConnectorConfig(service_id="starterproject", location=123, connector="my_connector")

class TestDataConnect:
  def teardown_method(self, method):
    del method
    testutils.cleanup_apps()
  
  def test_init_property_assignment(self):
    cred = testutils.MockCredential()
    try:
      app = firebase_admin.initialize_app(cred, name="starter_app")
    except Exception:
      pytest.fail("initialize app has an error")
    
    try:
      data_connect_instance = dataconnect.DataConnect(app, BASE_CONFIG)
    except Exception:
      pytest.fail("DataConnect initialization failed.")

    assert data_connect_instance._app is app
    assert data_connect_instance._config is BASE_CONFIG
    assert data_connect_instance.app is app
    assert data_connect_instance.config is BASE_CONFIG

    assert data_connect_instance._app.name == "starter_app"
    assert data_connect_instance._config.service_id == "starterproject"

class TestDataConnectClientFactory:
  def teardown_method(self, method):
    del method
    testutils.cleanup_apps()  
  
  def setup_method(self):
    self.cred = testutils.MockCredential()
    self.app = firebase_admin.initialize_app(self.cred, name='starter_app')
    self.config1 = BASE_CONFIG
    self.config2 = dataconnect.ConnectorConfig(service_id='starterproject2', location='us-east4', connector='my_connector2')
  
  @mock.patch.object(dataconnect._DataConnectService, 'get_client', autospec=True)
  def test_client_successful(self, mock_get_client):
    mock_get_client.side_effect = lambda service, config: dataconnect.DataConnect(service._app, config)
    client_instance = dataconnect.client(self.config1, app=self.app)
    mock_get_client.assert_called_once_with(mock.ANY, self.config1)
    assert isinstance(client_instance, dataconnect.DataConnect)
    assert client_instance.config is self.config1
    assert client_instance.app is self.app
  
  @pytest.mark.parametrize("config_a, config_b, expect_same", [
      (dataconnect.ConnectorConfig("s", "l", "c"), dataconnect.ConnectorConfig("s", "l", "c_diff"), False),
      (dataconnect.ConnectorConfig("s", "l", "c"), dataconnect.ConnectorConfig("s", "l_diff", "c"), False),
      (dataconnect.ConnectorConfig("s", "l", "c"), dataconnect.ConnectorConfig("s_diff", "l", "c"), False),
      (dataconnect.ConnectorConfig("s", "l", "c"), dataconnect.ConnectorConfig("s", "l", "c"), True),
  ])
  def test_client_caching_permutations(self, config_a, config_b, expect_same):
    client_a = dataconnect.client(config_a, app=self.app)
    client_b = dataconnect.client(config_b, app=self.app)
    if expect_same:
      assert client_a is client_b
    else:
      assert client_a is not client_b
  
  def test_client_retrieval_different_apps_same_config(self):
    app2 = firebase_admin.initialize_app(self.cred, name='app2')

    client1 = dataconnect.client(self.config1, app=self.app)
    client2 = dataconnect.client(self.config1, app=app2)

    assert client1 is not client2
    assert client1.app is self.app
    assert client1.app is not client2.app
  
  def test_invalid_config_type(self):
    with pytest.raises(ValueError, match="Config must be of type firebase_admin.dataconnect.ConnectorConfig"):
      dataconnect.client('not-a-config', app=self.app)
  
  def test_invalid_app_type(self):
    with pytest.raises(ValueError, match="App must be of type firebase_admin.App"):
      dataconnect.client(self.config1, 'not-a-app')

  def test_client_default_app(self):
    default_app = firebase_admin.initialize_app(self.cred)
    client_instance = dataconnect.client(self.config1)
    assert client_instance.app is default_app

  def test_client_none_config(self):
    with pytest.raises(ValueError, match="Config must be of type firebase_admin.dataconnect.ConnectorConfig"):
      dataconnect.client(None, app=self.app)
  
class TestDataConnectService:
  def setup_method(self):
    self.cred = testutils.MockCredential()
    self.app = firebase_admin.initialize_app(self.cred, name='starter_app')
    self.service = dataconnect._DataConnectService(self.app)
  
  def teardown_method(self, method):
    del method
    testutils.cleanup_apps()

  def test_cache_hit(self):
    config = dataconnect.ConnectorConfig('s1', 'l1', 'c1')
    client1 = self.service.get_client(config)
    client2 = self.service.get_client(config)
    assert client1 is client2

    assert isinstance(client1, dataconnect.DataConnect)
    assert client1.config is config

  def test_cache_miss_on_different_config(self):
    config1 = dataconnect.ConnectorConfig('s1', 'l1', 'c1')
    config2 = dataconnect.ConnectorConfig('s2', 'l2', 'c2')
    client1 = self.service.get_client(config1)
    client2 = self.service.get_client(config2)
    assert client1 is not client2

  @pytest.mark.parametrize("config_a, config_b, expect_same", [
      (dataconnect.ConnectorConfig('s', 'l', 'c'), dataconnect.ConnectorConfig('s', 'l', 'c_diff'), False),
      (dataconnect.ConnectorConfig('s', 'l', 'c'), dataconnect.ConnectorConfig('s', 'l_diff', 'c'), False),
      (dataconnect.ConnectorConfig('s', 'l', 'c'), dataconnect.ConnectorConfig('s_diff', 'l', 'c'), False),
      (dataconnect.ConnectorConfig('s', 'l', 'c'), dataconnect.ConnectorConfig('s', 'l', 'c'), True),
  ])
  def test_complex_cache_key(self, config_a, config_b, expect_same):
    client_a = self.service.get_client(config_a)
    client_b = self.service.get_client(config_b)
    if expect_same:
      assert client_a is client_b
    else:
      assert client_a is not client_b

  def test_config_equivalence(self):
    config1 = dataconnect.ConnectorConfig('s1', 'l1', 'c1')
    config2 = dataconnect.ConnectorConfig('s1', 'l1', 'c1')
    client1 = self.service.get_client(config1)
    client2 = self.service.get_client(config2)
    assert client1 is client2

  @mock.patch('firebase_admin.dataconnect.DataConnect', autospec=True)
  def test_client_creation_mocking(self, MockDataConnect):
    config1 = dataconnect.ConnectorConfig('s_mock', 'l_mock', 'c_mock1')
    config2 = dataconnect.ConnectorConfig('s_mock', 'l_mock', 'c_mock2')

    self.service.get_client(config1)
    MockDataConnect.assert_called_once_with(app=self.app, config=config1)

    MockDataConnect.reset_mock()

    self.service.get_client(config1)
    MockDataConnect.assert_not_called()

    MockDataConnect.reset_mock()

    # first call using config2
    self.service.get_client(config2)
    MockDataConnect.assert_called_once_with(app=self.app, config=config2)

  @mock.patch('firebase_admin.dataconnect.DataConnect', autospec=True)
  def test_error_handling_in_creation(self, MockDataConnect):
    config = dataconnect.ConnectorConfig('s_err', 'l_err', 'c_err')
    test_error = RuntimeError("Failed to create client")
    MockDataConnect.side_effect = test_error

    with pytest.raises(RuntimeError, match="Failed to create client"):
      self.service.get_client(config)

    # Ensure the failed creation wasn't cached
    MockDataConnect.side_effect = None
    self.service.get_client(config)
    assert MockDataConnect.call_count == 2

  def test_invalid_config_in_service(self):
    with pytest.raises(ValueError, match="Config must be of type firebase_admin.dataconnect.ConnectorConfig"):
      self.service.get_client(None)

class TestDataConnectServiceIntegration:
  def setup_method(self):
    self.cred = testutils.MockCredential()
    self.app1 = firebase_admin.initialize_app(self.cred, name='integ_app1')
    self.app2 = firebase_admin.initialize_app(self.cred, name='integ_app2')

    self.config1 = BASE_CONFIG
    self.config2 = dataconnect.ConnectorConfig(service_id='service2', location='us-east4', connector='conn2')
    self.config1_copy = dataconnect.ConnectorConfig(service_id='starterproject', location='us-east4', connector='my_connector')
  
  def teardown_method(self, method):
    del method
    testutils.cleanup_apps()
  
  def test_overall_client_retrieval_and_caching(self):
    client1a = dataconnect.client(self.config1, app=self.app1)
    client1b = dataconnect.client(self.config1_copy, app=self.app1)
    client2 = dataconnect.client(self.config2, app=self.app1)

    assert isinstance(client1a, dataconnect.DataConnect), "Client should be a DataConnect instance"
    assert client1a.app is self.app1, "Client should be associated with app1"
    assert client1a.config is self.config1, "Client should hold the specific config1"

    # Same config
    assert client1b is client1a, "Client should be cached for an equivalent config on the same app"

    # Different config
    assert isinstance(client2, dataconnect.DataConnect), "Client should be a DataConnect instance"
    assert client2.app is self.app1, "Client should be associated with app1"
    assert client2.config is self.config2, "Client should hold the specific config2"
    assert client2 is not client1a, "Clients with different configs should be different instances"

    # Different app
    client1_app2 = dataconnect.client(self.config1, app=self.app2)

    assert isinstance(client1_app2, dataconnect.DataConnect), "Client on app2 should be a DataConnect instance"
    assert client1_app2.app is self.app2, "Client should be associated with app2"
    assert client1_app2.config is self.config1, "Client on app2 should hold config1"
    assert client1_app2 is not client1a, "Clients on different apps should be different instances"

  @mock.patch.object(_utils, 'get_app_service', wraps=_utils.get_app_service)
  def test_uses_app_service_mechanism(self, mock_get_app_service):
    """Ensures dataconnect.client uses the standard app service loader."""
    dataconnect.client(self.config1, app=self.app1)
    mock_get_app_service.assert_called_once()
    args, _ = mock_get_app_service.call_args
    assert args[0] is self.app1
    assert args[1] == '_data_connect_service'
    assert args[2] == dataconnect._DataConnectService
  