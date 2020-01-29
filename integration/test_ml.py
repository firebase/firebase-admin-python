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
import re
import os
import shutil
import unittest
import pytest


from firebase_admin import ml
from firebase_admin import exceptions
from tests import testutils


# pylint: disable=import-error,no-name-in-module
try:
    import tensorflow as tf
    _TF_ENABLED = True
except ImportError:
    _TF_ENABLED = False


NAME_ONLY_ARGS = {
    'display_name': 'TestModel123'
}
NAME_AND_TAGS_ARGS = {
    'display_name': 'TestModel123_tags',
    'tags': ['test_tag123']
    }
FULL_MODEL_ARGS = {
    'display_name': 'TestModel123_full',
    'tags': ['test_tag567'],
    'file_name': 'model1.tflite'
    }
INVALID_FULL_MODEL_ARGS = {
    'display_name': 'TestModel123_invalid_full',
    'tags': ['test_tag890'],
    'file_name': 'invalid_model.tflite'
    }

@pytest.fixture
def firebase_model(request):
    args = request.param
    tflite_format = None
    if args.get('file_name'):
        file_path = testutils.resource_filename(args.get('file_name'))
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
    ml_model_1 = ml.Model(display_name="TestModel123")
    model_1 = ml.create_model(model=ml_model_1)

    ml_model_2 = ml.Model(display_name="TestModel123_tags", tags=['test_tag123'])
    model_2 = ml.create_model(model=ml_model_2)

    yield [model_1, model_2]

    _clean_up_model(model_1)
    _clean_up_model(model_2)


def _clean_up_model(model):
    try:
        # Try to delete the model.
        # Some tests delete the model as part of the test.
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


@pytest.mark.parametrize('firebase_model', [NAME_AND_TAGS_ARGS], indirect=True)
def test_create_simple_model(firebase_model):
    assert firebase_model.display_name == NAME_AND_TAGS_ARGS.get('display_name')
    assert firebase_model.tags == NAME_AND_TAGS_ARGS.get('tags')
    assert firebase_model.model_id is not None
    assert firebase_model.create_time is not None
    assert firebase_model.update_time is not None
    assert firebase_model.validation_error == 'No model file has been uploaded.'
    assert firebase_model.locked is False
    assert firebase_model.published is False
    assert firebase_model.etag is not None
    assert firebase_model.model_hash is None
    assert firebase_model.model_format is None


@pytest.mark.parametrize('firebase_model', [FULL_MODEL_ARGS], indirect=True)
def test_create_full_model(firebase_model):
    assert firebase_model.display_name == FULL_MODEL_ARGS.get('display_name')
    assert firebase_model.tags == FULL_MODEL_ARGS.get('tags')
    assert firebase_model.model_format.size_bytes is not None
    assert firebase_model.model_format.model_source.gcs_tflite_uri is not None
    assert firebase_model.model_id is not None
    assert firebase_model.create_time is not None
    assert firebase_model.update_time is not None
    assert firebase_model.validation_error is None
    assert firebase_model.locked is False
    assert firebase_model.published is False
    assert firebase_model.etag is not None
    assert firebase_model.model_hash is not None


@pytest.mark.parametrize('firebase_model', [FULL_MODEL_ARGS], indirect=True)
def test_create_already_existing_fails(firebase_model):
    with pytest.raises(exceptions.AlreadyExistsError) as excinfo:
        ml.create_model(model=firebase_model)
    check_operation_error(
        excinfo,
        'Model \'{0}\' already exists'.format(firebase_model.display_name))


@pytest.mark.parametrize('firebase_model', [INVALID_FULL_MODEL_ARGS], indirect=True)
def test_create_invalid_model(firebase_model):
    assert firebase_model.display_name == INVALID_FULL_MODEL_ARGS.get('display_name')
    assert firebase_model.tags == INVALID_FULL_MODEL_ARGS.get('tags')
    assert firebase_model.model_format.size_bytes is None
    assert firebase_model.model_format.model_source.gcs_tflite_uri is not None
    assert firebase_model.model_id is not None
    assert firebase_model.create_time is not None
    assert firebase_model.update_time is not None
    assert firebase_model.validation_error == 'Invalid flatbuffer format'
    assert firebase_model.locked is False
    assert firebase_model.published is False
    assert firebase_model.etag is not None
    assert firebase_model.model_hash is None


@pytest.mark.parametrize('firebase_model', [NAME_AND_TAGS_ARGS], indirect=True)
def test_get_model(firebase_model):
    get_model = ml.get_model(firebase_model.model_id)
    assert get_model.display_name == firebase_model.display_name
    assert get_model.tags == firebase_model.tags
    assert get_model.model_id is not None
    assert get_model.create_time is not None
    assert get_model.update_time is not None
    assert get_model.validation_error == 'No model file has been uploaded.'
    assert get_model.etag is not None
    assert get_model.locked is False
    assert get_model.published is False
    assert get_model.model_hash is None


@pytest.mark.parametrize('firebase_model', [NAME_ONLY_ARGS], indirect=True)
def test_get_non_existing_model(firebase_model):
    # Get a valid model_id that no longer exists
    ml.delete_model(firebase_model.model_id)

    with pytest.raises(exceptions.NotFoundError) as excinfo:
        ml.get_model(firebase_model.model_id)
    check_firebase_error(excinfo, 404, 'Requested entity was not found.')


@pytest.mark.parametrize('firebase_model', [NAME_ONLY_ARGS], indirect=True)
def test_update_model(firebase_model):
    new_model_name = 'TestModel123_updated'
    firebase_model.display_name = new_model_name

    updated_model = ml.update_model(firebase_model)
    assert updated_model.display_name == new_model_name
    assert updated_model.model_id == firebase_model.model_id
    assert updated_model.create_time == firebase_model.create_time
    assert updated_model.update_time != firebase_model.update_time
    assert updated_model.validation_error == firebase_model.validation_error
    assert updated_model.etag != firebase_model.etag
    assert updated_model.published == firebase_model.published
    assert updated_model.locked == firebase_model.locked

    # Second call with same model does not cause error
    updated_model2 = ml.update_model(updated_model)
    assert updated_model2.display_name == updated_model.display_name
    assert updated_model2.model_id == updated_model.model_id
    assert updated_model2.create_time == updated_model.create_time
    assert updated_model2.update_time != updated_model.update_time
    assert updated_model2.validation_error == updated_model.validation_error
    assert updated_model2.etag != updated_model.etag
    assert updated_model2.published == updated_model.published
    assert updated_model2.locked == updated_model.locked


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

    models_list = ml.list_models(list_filter=filter_str)
    assert len(models_list.models) == 2
    for mdl in models_list.models:
        assert mdl == model_list[0] or mdl == model_list[1]
    assert models_list.models[0] != models_list.models[1]


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
#'pip install tensorflow==2.0.0b' for version 2 etc.


SAVED_MODEL_DIR = '/tmp/saved_model/1'


def _clean_up_tmp_directory():
    if os.path.exists(SAVED_MODEL_DIR):
        shutil.rmtree(SAVED_MODEL_DIR)


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
    # different versions have different model conversion capability
    # pick something that works for each version
    save_dir = SAVED_MODEL_DIR
    _clean_up_tmp_directory() # previous failures may leave files
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
    _clean_up_tmp_directory()


@unittest.skipUnless(_TF_ENABLED, 'Tensor flow is required for this test.')
def test_from_keras_model(keras_model):
    source = ml.TFLiteGCSModelSource.from_keras_model(keras_model, 'model2.tflite')
    assert re.search(
        '^gs://.*/Firebase/ML/Models/model2.tflite$',
        source.gcs_tflite_uri) is not None

    # Validate the conversion by creating a model
    try:
        model_format = ml.TFLiteFormat(model_source=source)
        model = ml.Model(display_name="KerasModel1", model_format=model_format)
        created_model = ml.create_model(model)
        assert created_model.model_id is not None
        assert created_model.validation_error is None
    finally:
        _clean_up_model(created_model)


@unittest.skipUnless(_TF_ENABLED, 'Tensor flow is required for this test.')
def test_from_saved_model(saved_model_dir):
    # Test the conversion helper
    source = ml.TFLiteGCSModelSource.from_saved_model(saved_model_dir, 'model3.tflite')
    assert re.search(
        '^gs://.*/Firebase/ML/Models/model3.tflite$',
        source.gcs_tflite_uri) is not None

    # Validate the conversion by creating a model
    try:
        model_format = ml.TFLiteFormat(model_source=source)
        model = ml.Model(display_name="SavedModel1", model_format=model_format)
        created_model = ml.create_model(model)
        assert created_model.model_id is not None
        assert created_model.validation_error is None
    finally:
        _clean_up_model(created_model)
