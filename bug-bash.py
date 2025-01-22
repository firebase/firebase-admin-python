import firebase_admin
from firebase_admin import credentials
from firebase_admin import remote_config
import asyncio

# Evaluate the template and manually assert the config
def test_evaluations(template):
    # [Bug Bash 101] Custom Signals
    # Evaluate template - pass custom signals
    # Update the custom signals being passed in evaluate to test how variations of the 
    # signals cause changes to the config evaluation.
    config = template.evaluate(
          # Update custom vars 
          {
            'custom_key_str': 'custom_val_str',
            'version_key': '12.1.3.-1'
          }
        )

    # [Bug Bash 101] Verify Evaluation
    # Update the following print statements to verify if config is being created properly.
    # Print default config values 
    print('[Default Config] default_key_str: ', config.get_string('default_key_str'))
    print('[Default Config] default_key_number: ', config.get_int('default_key_number'))

    # Verify evaluated config
    print('[Evluated Config] Config values:', config.get_string('rc_testx'))

    # Verify value and source for configs
    print('Value Source:', config.get_value_source('test_server'))
    
    print('----------------')

def bug_bash():
  # [Bug Bash 101] Credentials
  # Load creds for authentication - Update the json key from the one downloaded from the console.
  cred = credentials.Certificate('credentials.json')
  default_app = firebase_admin.initialize_app(cred)

  # [Bug Bash 101] Default Config
  # Create default template for initializing ServerTemplate
  # For bug bash, update the default config to any config that you want to initialize
  # the app with. The configs will be cached and might get updated during evaluation of the template.
  default_config = {
      'rc_test_3': 'default_val_str',
      'rc_testx': 'val_str'
  }

  # Create initial template
  template = remote_config.init_server_template(app=default_app, default_config=default_config)

  # Load the template from the backend
  asyncio.run(template.load())

  test_evaluations(template)

  # Verify template initialization from saved JSON
  template_json = template.to_json()
  template_v2 = remote_config.init_server_template(app=default_app, 
                                                default_config=default_config, 
                                                template_data_json=template_json)
  
  test_evaluations(template_v2)

bug_bash()






