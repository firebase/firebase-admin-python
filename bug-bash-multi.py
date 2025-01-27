from threading import Thread
from time import monotonic, sleep
import firebase_admin
from firebase_admin import credentials
from firebase_admin import remote_config
import asyncio

# Evaluate the template and manually assert the config
def test_evaluations(template):
    for i in range(1,10):
        config = template.evaluate(
            # Update custom vars 
            {
                'custom_key_str': 'custom_val_str',
                'version_key': '12.1.3.-1',
                'randomization_id': 'abc',
            }
        )
        print('[E',i,']',monotonic(),'Evaluated Template: {test1:', config.get_string('test1'), '[source: ', config.get_value_source('test1'),
              '], test: ', config.get_string('test2'), '[source: ', config.get_value_source('test2'), ']}')
        sleep(1)

def bug_bash_t():
  # [Bug Bash 101] Credentials
  # Load creds for authentication - Update the json key from the one downloaded from the console.
  cred = credentials.Certificate('creds.json')
  default_app = firebase_admin.initialize_app(cred)

  # [Bug Bash 101] Default Config
  # Create default template for initializing ServerTemplate
  # For bug bash, update the default config to any config that you want to initialize
  # the app with. The configs will be cached and might get updated during evaluation of the template.
  default_config = {
      'rc_test_3': 'default_val_str',
      'rc_testx': 'val_str',
      'test2': 'default_test'
  }

  # Create initial template
  template = remote_config.init_server_template(app=default_app, default_config=default_config)

  # Load the template from the backend
  asyncio.run(template.load())
  thread1 = Thread(target = test_evaluations, args = (template,))
  thread1.start()
  sleep(0.5)
  for i in range (1,10):
    sleep(1)
    print('[L',i,']',monotonic(),' Loading new template')
    asyncio.run(template.load())

  thread1.join()

bug_bash_t()






