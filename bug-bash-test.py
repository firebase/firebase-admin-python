import firebase_admin
from firebase_admin import credentials
from firebase_admin import remote_config
import asyncio

# [Bug Bash 101] Credentials
# Load creds for authentication - Update the json key from the one downloaded from the console.
cred = credentials.Certificate('private-api-key.json.json')
default_app = firebase_admin.initialize_app(cred)

# [Bug Bash 101] Default Config
# Create default template for initializing ServerTemplate
# For bug bash, update the default config to any config that you want to initialize
# the app with. The configs will be cached and might get updated during evaluation of the template.
default_config = {
    'default_key_str': 'default_val_str',
    'default_key_number': 123
}

# Create initial template
template = remote_config.init_server_template(app=default_app, default_config=default_config)

# Load the template from the backend
asyncio.run(template.load())

# [Bug Bash 101] Custom Signals
# Evaluate template - pass custom signals
# Update the custom signals being passed in evaluate to test how variations of the 
# signals cause changes to the config evaluation.
config = template.evaluate(
      # Update custom vars 
      {
        'custom_key_str': 'custom_val_str',
        'custom_key_int': 123
      }
    )

# [Bug Bash 101] Verify Evaluation
# Update the following print statements to verify if config is being created properly.
# Print default config values 
print('[Default Config] default_key_str: ', config.get_string('default_key_str'))
print('[Default Config] default_key_number: ', config.get_int('default_key_number'))

# Verify evaluated config
print('[Evluated Config] Config values:', config.get_float('ssrc_test_key_float'))
print('[Evluated Config] Config values:', config.get_boolean('ssrc_test_key_bool'))

# Verify value and source for configs
print('Config Value:', config.get_value('ssrc_test_key').as_string(), 
      'Value Source:', config.get_value('ssrc_test_key').get_source())
