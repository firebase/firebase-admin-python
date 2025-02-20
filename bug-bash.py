import json
import firebase_admin
from firebase_admin import credentials
from firebase_admin import remote_config
import asyncio

# Evaluate the template and manually assert the config
def test_evaluations(template):
    # Custom Signals
    # signals cause changes to the config evaluation.
    config = template.evaluate(
          # Update custom vars 
          {
             'randomization_id': 'random',
             'custom_str': 'custom_val'
          }
        )

    # Print default config values 
    print('[Default Config] default_key_str: ', config.get_string('rc_test_y'))

    # Verify evaluated config
    print('[Evluated Config] Config values:', config.get_string('rc_test_x'))

    # Verify value and source for configs
    print('Value Source:', config.get_value_source('rc_test_x'))
    
    print('----------------')

def fetchServerTemplateAndStoreTemplate(default_app, default_config):
  # Create initial template
  template = remote_config.init_server_template(app=default_app, default_config=default_config)

  # Load the template from the backend
  asyncio.run(template.load())

  template_json = template.to_json()
 
  f = open("template.json", "w")
  json.dump(template_json,f)
  f.close()

  return template

def initializeTempalteFromLocalStorage(default_app, default_config):
  # Verify template initialization from saved JSON
  f = open("template.json", "r")
  template_json = json.load(f)
  return remote_config.init_server_template(app=default_app, 
                                               default_config=default_config, 
                                               template_data_json=template_json)
  

def bug_bash():
  # Load creds for authentication - Update the json key from the one downloaded from the console.
  cred = credentials.Certificate('credentials.json')
  default_app = firebase_admin.initialize_app(cred)

  # Default config with default values used to initialize template
  default_config = {
     'rc_test_x': 'rc_default_x',
     'rc_test_y': 'rc_default_y'
  }

  # template = fetchServerTemplateAndStoreTemplate(default_app,default_config)

  template = initializeTempalteFromLocalStorage(default_app,default_config)

  # Evaluate Template
  test_evaluations(template)
  
bug_bash()






