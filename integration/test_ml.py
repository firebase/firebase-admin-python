# Copyright 2020 Google Inc.
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

"""Integration tests for firebase_admin.ml module."""
import os
import random
import re
import shutil
import string
import tempfile

import pytest

import firebase_admin
from firebase_admin import exceptions
from firebase_admin import ml
from tests import testutils


# pylint: disable=import-error,no-name-in-module
try:
    import tensorflow as tf
    _TF_ENABLED = True
except ImportError:
    _TF_ENABLED = False

try:
    from google.cloud import automl_v1
    _AUTOML_ENABLED = True
except ImportError:
    _AUTOML_ENABLED = False

def _random_identifier(prefix):
    #pylint: disable=unused-variable
    suffix = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(8)])
    return '{0}_{1}'.format(prefix, suffix)


NAME_ONLY_ARGS = {
    'display_name': _random_identifier('TestModel_')
}
NAME_ONLY_ARGS_UPDATED = {
    'display_name': _random_identifier('TestModel_updated_')
}
NAME_AND_TAGS_ARGS = {
    'display_name': _random_identifier('TestModel_tags_'),
    'tags': ['test_tag123']
}
FULL_MODEL_ARGS = {
    'display_name': _random_identifier('TestModel_full_'),
    'tags': ['test_tag567'],
    'file_name': 'model1.tflite'
}
INVALID_FULL_MODEL_ARGS = {
    'display_name': _random_identifier('TestModel_invalid_full_'),
    'tags': ['test_tag890'],
    'file_name': 'invalid_model.tflite'
}

@pytest.fixture
def firebase_model(request):
    args = request.param
    tflite_format = None
    file_name = args.get('file_name')
    if file_name:
        file_path = testutils.resource_filename(file_name)
        source = ml.TFLiteGCSModelSource.from_tflite_model_file(file_path)
        tflite_format = ml.TFLiteFormat(model_source=source)

    ml_model = ml.Model(
        display_name=args.get('display_name'),
        tags=args.get('tags'),
        model_format=tflite_format)
    model = ml.create_model(model=ml_model)
    yield model
    _clean_up_model(model)


@pytest.fixture
def model_list():
    ml_model_1 = ml.Model(display_name=_random_identifier('TestModel123_list1_'))
    model_1 = ml.create_model(model=ml_model_1)

    ml_model_2 = ml.Model(display_name=_random_identifier('TestModel123_list2_'),
                          tags=['test_tag123'])
    model_2 = ml.create_model(model=ml_model_2)

    yield [model_1, model_2]

    _clean_up_model(model_1)
    _clean_up_model(model_2)


def _clean_up_model(model):
    try:
        # Try to delete the model.
        # Some tests delete the model as part of the test.
        model.wait_for_unlocked()
        ml.delete_model(model.model_id)
    except exceptions.NotFoundError:
        pass


# For rpc errors
def check_firebase_error(excinfo, status, msg):
    err = excinfo.value
    assert isinstance(err, exceptions.FirebaseError)
    assert err.cause is not None
    assert err.http_response is not None
    assert err.http_response.status_code == status
    assert str(err) == msg


# For operation errors
def check_operation_error(excinfo, msg):
    err = excinfo.value
    assert isinstance(err, exceptions.FirebaseError)
    assert str(err) == msg


def check_model(model, args):
    assert model.display_name == args.get('display_name')
    assert model.tags == args.get('tags')
    assert model.model_id is not None
    assert model.create_time is not None
    assert model.update_time is not None
    assert model.locked is False
    assert model.etag is not None

# Model Format Checks

def check_no_model_format(model):
    assert model.model_format is None
    assert model.validation_error == 'No model file has been uploaded.'
    assert model.published is False
    assert model.model_hash is None


def check_tflite_gcs_format(model, validation_error=None):
    assert model.validation_error == validation_error
    assert model.published is False
    assert model.model_format.model_source.gcs_tflite_uri.startswith('gs://')
    if validation_error:
        assert model.model_format.size_bytes is None
        assert model.model_hash is None
    else:
        assert model.model_format.size_bytes is not None
        assert model.model_hash is not None


def check_tflite_automl_format(model):
    assert model.validation_error is None
    assert model.published is False
    assert model.model_format.model_source.auto_ml_model.startswith('projects/')
    # Automl models don't have validation errors since they are references
    # to valid automl models.


@pytest.mark.parametrize('firebase_model', [NAME_AND_TAGS_ARGS], indirect=True)
def test_create_simple_model(firebase_model):
    check_model(firebase_model, NAME_AND_TAGS_ARGS)
    check_no_model_format(firebase_model)


@pytest.mark.parametrize('firebase_model', [FULL_MODEL_ARGS], indirect=True)
def test_create_full_model(firebase_model):
    check_model(firebase_model, FULL_MODEL_ARGS)
    check_tflite_gcs_format(firebase_model)


@pytest.mark.parametrize('firebase_model', [FULL_MODEL_ARGS], indirect=True)
def test_create_already_existing_fails(firebase_model):
    with pytest.raises(exceptions.AlreadyExistsError) as excinfo:
        ml.create_model(model=firebase_model)
    check_operation_error(
        excinfo,
        'Model \'{0}\' already exists'.format(firebase_model.display_name))


@pytest.mark.parametrize('firebase_model', [INVALID_FULL_MODEL_ARGS], indirect=True)
def test_create_invalid_model(firebase_model):
    check_model(firebase_model, INVALID_FULL_MODEL_ARGS)
    check_tflite_gcs_format(firebase_model, 'Invalid flatbuffer format')


@pytest.mark.parametrize('firebase_model', [NAME_AND_TAGS_ARGS], indirect=True)
def test_get_model(firebase_model):
    get_model = ml.get_model(firebase_model.model_id)
    check_model(get_model, NAME_AND_TAGS_ARGS)
    check_no_model_format(get_model)


@pytest.mark.parametrize('firebase_model', [NAME_ONLY_ARGS], indirect=True)
def test_get_non_existing_model(firebase_model):
    # Get a valid model_id that no longer exists
    ml.delete_model(firebase_model.model_id)

    with pytest.raises(exceptions.NotFoundError) as excinfo:
        ml.get_model(firebase_model.model_id)
    check_firebase_error(excinfo, 404, 'Requested entity was not found.')


@pytest.mark.parametrize('firebase_model', [NAME_ONLY_ARGS], indirect=True)
def test_update_model(firebase_model):
    new_model_name = NAME_ONLY_ARGS_UPDATED.get('display_name')
    firebase_model.display_name = new_model_name
    updated_model = ml.update_model(firebase_model)
    check_model(updated_model, NAME_ONLY_ARGS_UPDATED)
    check_no_model_format(updated_model)

    # Second call with same model does not cause error
    updated_model2 = ml.update_model(updated_model)
    check_model(updated_model2, NAME_ONLY_ARGS_UPDATED)
    check_no_model_format(updated_model2)


@pytest.mark.parametrize('firebase_model', [NAME_ONLY_ARGS], indirect=True)
def test_update_non_existing_model(firebase_model):
    ml.delete_model(firebase_model.model_id)

    firebase_model.tags = ['tag987']
    with pytest.raises(exceptions.NotFoundError) as excinfo:
        ml.update_model(firebase_model)
    check_operation_error(
        excinfo,
        'Model \'{0}\' was not found'.format(firebase_model.as_dict().get('name')))


@pytest.mark.parametrize('firebase_model', [FULL_MODEL_ARGS], indirect=True)
def test_publish_unpublish_model(firebase_model):
    assert firebase_model.published is False

    published_model = ml.publish_model(firebase_model.model_id)
    assert published_model.published is True

    unpublished_model = ml.unpublish_model(published_model.model_id)
    assert unpublished_model.published is False


@pytest.mark.parametrize('firebase_model', [NAME_ONLY_ARGS], indirect=True)
def test_publish_invalid_fails(firebase_model):
    assert firebase_model.validation_error is not None

    with pytest.raises(exceptions.FailedPreconditionError) as excinfo:
        ml.publish_model(firebase_model.model_id)
    check_operation_error(
        excinfo,
        'Cannot publish a model that is not verified.')


@pytest.mark.parametrize('firebase_model', [FULL_MODEL_ARGS], indirect=True)
def test_publish_unpublish_non_existing_model(firebase_model):
    ml.delete_model(firebase_model.model_id)

    with pytest.raises(exceptions.NotFoundError) as excinfo:
        ml.publish_model(firebase_model.model_id)
    check_operation_error(
        excinfo,
        'Model \'{0}\' was not found'.format(firebase_model.as_dict().get('name')))

    with pytest.raises(exceptions.NotFoundError) as excinfo:
        ml.unpublish_model(firebase_model.model_id)
    check_operation_error(
        excinfo,
        'Model \'{0}\' was not found'.format(firebase_model.as_dict().get('name')))


def test_list_models(model_list):
    filter_str = 'displayName={0} OR tags:{1}'.format(
        model_list[0].display_name, model_list[1].tags[0])

    all_models = ml.list_models(list_filter=filter_str)
    all_model_ids = [mdl.model_id for mdl in all_models.iterate_all()]
    for mdl in model_list:
        assert mdl.model_id in all_model_ids


def test_list_models_invalid_filter():
    invalid_filter = 'InvalidFilterParam=123'

    with pytest.raises(exceptions.InvalidArgumentError) as excinfo:
        ml.list_models(list_filter=invalid_filter)
    check_firebase_error(excinfo, 400, 'Request contains an invalid argument.')


@pytest.mark.parametrize('firebase_model', [NAME_ONLY_ARGS], indirect=True)
def test_delete_model(firebase_model):
    ml.delete_model(firebase_model.model_id)

    # Second delete of same model will fail
    with pytest.raises(exceptions.NotFoundError) as excinfo:
        ml.delete_model(firebase_model.model_id)
    check_firebase_error(excinfo, 404, 'Requested entity was not found.')


# Test tensor flow conversion functions if tensor flow is enabled.
#'pip install tensorflow' in the environment if you want _TF_ENABLED = True
#'pip install tensorflow==2.2.0' for version 2.2.0 etc.


def _clean_up_directory(save_dir):
    if save_dir.startswith(tempfile.gettempdir()) and os.path.exists(save_dir):
        shutil.rmtree(save_dir)


@pytest.fixture
def keras_model():
    assert _TF_ENABLED
    x_array = [-1, 0, 1, 2, 3, 4]
    y_array = [-3, -1, 1, 3, 5, 7]
    model = tf.keras.models.Sequential(
        [tf.keras.layers.Dense(units=1, input_shape=[1])])
    model.compile(optimizer='sgd', loss='mean_squared_error')
    model.fit(x_array, y_array, epochs=3)
    return model


@pytest.fixture
def saved_model_dir(keras_model):
    assert _TF_ENABLED
    # Make a new parent directory. The child directory must not exist yet.
    # The child directory gets created by tf. If it exists, the tf call fails.
    parent = tempfile.mkdtemp()
    save_dir = os.path.join(parent, 'child')

    # different versions have different model conversion capability
    # pick something that works for each version
    if tf.version.VERSION.startswith('1.'):
        tf.reset_default_graph()
        x_var = tf.placeholder(tf.float32, (None, 3), name="x")
        y_var = tf.multiply(x_var, x_var, name="y")
        with tf.Session() as sess:
            tf.saved_model.simple_save(sess, save_dir, {"x": x_var}, {"y": y_var})
    else:
        # If it's not version 1.x or version 2.x we need to update the test.
        assert tf.version.VERSION.startswith('2.')
        tf.saved_model.save(keras_model, save_dir)
    yield save_dir
    _clean_up_directory(parent)



@pytest.mark.skipif(not _TF_ENABLED, reason='Tensor flow is required for this test.')
def test_from_keras_model(keras_model):
    source = ml.TFLiteGCSModelSource.from_keras_model(keras_model, 'model2.tflite')
    assert re.search(
        '^gs://.*/Firebase/ML/Models/model2.tflite$',
        source.gcs_tflite_uri) is not None

    # Validate the conversion by creating a model
    model_format = ml.TFLiteFormat(model_source=source)
    model = ml.Model(display_name=_random_identifier('KerasModel_'), model_format=model_format)
    created_model = ml.create_model(model)

    try:
        check_model(created_model, {'display_name': model.display_name})
        check_tflite_gcs_format(created_model)
    finally:
        _clean_up_model(created_model)


@pytest.mark.skipif(not _TF_ENABLED, reason='Tensor flow is required for this test.')
def test_from_saved_model(saved_model_dir):
    # Test the conversion helper
    source = ml.TFLiteGCSModelSource.from_saved_model(saved_model_dir, 'model3.tflite')
    assert re.search(
        '^gs://.*/Firebase/ML/Models/model3.tflite$',
        source.gcs_tflite_uri) is not None

    # Validate the conversion by creating a model
    model_format = ml.TFLiteFormat(model_source=source)
    model = ml.Model(display_name=_random_identifier('SavedModel_'), model_format=model_format)
    created_model = ml.create_model(model)

    try:
        assert created_model.model_id is not None
        assert created_model.validation_error is None
    finally:
        _clean_up_model(created_model)


# Test AutoML functionality if AutoML is enabled.
#'pip install google-cloud-automl' in the environment if you want _AUTOML_ENABLED = True
# You will also need a predefined AutoML model named 'admin_sdk_integ_test1' to run the
# successful test. (Test is skipped otherwise)

@pytest.fixture
def automl_model():
    assert _AUTOML_ENABLED

    # It takes > 20 minutes to train a model, so we expect a predefined AutoMl
    # model named 'admin_sdk_integ_test1' to exist in the project, or we skip
    # the test.
    automl_client = automl_v1.AutoMlClient()
    project_id = firebase_admin.get_app().project_id
    parent = automl_client.location_path(project_id, 'us-central1')
    models = automl_client.list_models(parent, filter_="display_name=admin_sdk_integ_test1")
    # Expecting exactly one. (Ok to use last one if somehow more than 1)
    automl_ref = None
    for model in models:
        automl_ref = model.name

    # Skip if no pre-defined model. (It takes min > 20 minutes to train a model)
    if automl_ref is None:
        pytest.skip("No pre-existing AutoML model found. Skipping test")

    source = ml.TFLiteAutoMlSource(automl_ref)
    tflite_format = ml.TFLiteFormat(model_source=source)
    ml_model = ml.Model(
        display_name=_random_identifier('TestModel_automl_'),
        tags=['test_automl'],
        model_format=tflite_format)
    model = ml.create_model(model=ml_model)
    yield model
    _clean_up_model(model)

@pytest.mark.skipif(not _AUTOML_ENABLED, reason='AutoML is required for this test.')
def test_automl_model(automl_model):
  # This test looks for a predefined automl model with display_name = 'admin_sdk_integ_test1'
    automl_model.wait_for_unlocked()

    check_model(automl_model, {
        'display_name': automl_model.display_name,
        'tags': ['test_automl'],
    })
    check_tflite_automl_format(automl_model)
