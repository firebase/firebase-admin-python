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
import pytest


from firebase_admin import ml
from firebase_admin import exceptions
from tests import testutils


# pylint: disable=import-error,no-name-in-module
try:
    import tensorflow as tf
    import os      # This is only needed for the tensorflow testing
    import shutil  # This is only needed for the tensorflow testing
    _TF_ENABLED = True
except ImportError:
    _TF_ENABLED = False


@pytest.fixture
def name_only_model():
    model = ml.Model(display_name="TestModel123")
    yield model


@pytest.fixture
def name_and_tags_model():
    model = ml.Model(display_name="TestModel123_tags", tags=['test_tag123'])
    yield model


@pytest.fixture
def full_model():
    tflite_file_name = testutils.resource_filename('model1.tflite')
    source1 = ml.TFLiteGCSModelSource.from_tflite_model_file(tflite_file_name)
    format1 = ml.TFLiteFormat(model_source=source1)
    model = ml.Model(
        display_name="TestModel123_full",
        tags=['test_tag567'],
        model_format=format1)
    yield model


@pytest.fixture
def invalid_full_model():
    tflite_file_name = testutils.resource_filename('invalid_model.tflite')
    source1 = ml.TFLiteGCSModelSource.from_tflite_model_file(tflite_file_name)
    format1 = ml.TFLiteFormat(model_source=source1)
    model = ml.Model(
        display_name="TestModel123_invalid_full",
        tags=['test_tag890'],
        model_format=format1)
    yield model


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


def _ensure_model_exists(model):
    # Delete any previously existing model with the same name because
    # it may be modified from the model that is passed in.
    _delete_if_exists(model)

    # And recreate using the model passed in
    created_model = ml.create_model(model=model)
    return created_model


# Use this when you know the model_id and are sure it exists.
def _clean_up_model(model):
    ml.delete_model(model.model_id)


# Use this when you don't know the model_id or it may not exist.
def _delete_if_exists(model):
    filter_str = 'displayName={0}'.format(model.display_name)
    models_list = ml.list_models(list_filter=filter_str)
    for mdl in models_list.models:
        ml.delete_model(mdl.model_id)


def test_create_simple_model(name_and_tags_model):
    _delete_if_exists(name_and_tags_model)

    firebase_model = ml.create_model(model=name_and_tags_model)
    assert firebase_model.display_name == name_and_tags_model.display_name
    assert firebase_model.tags == name_and_tags_model.tags
    assert firebase_model.model_id is not None
    assert firebase_model.create_time is not None
    assert firebase_model.update_time is not None
    assert firebase_model.validation_error == 'No model file has been uploaded.'
    assert firebase_model.locked is False
    assert firebase_model.published is False
    assert firebase_model.etag is not None
    assert firebase_model.model_hash is None

    _clean_up_model(firebase_model)

def test_create_full_model(full_model):
    _delete_if_exists(full_model)

    firebase_model = ml.create_model(model=full_model)
    assert firebase_model.display_name == full_model.display_name
    assert firebase_model.tags == full_model.tags
    assert firebase_model.model_format.size_bytes is not None
    assert firebase_model.model_format.model_source == full_model.model_format.model_source
    assert firebase_model.model_id is not None
    assert firebase_model.create_time is not None
    assert firebase_model.update_time is not None
    assert firebase_model.validation_error is None
    assert firebase_model.locked is False
    assert firebase_model.published is False
    assert firebase_model.etag is not None
    assert firebase_model.model_hash is not None

    _clean_up_model(firebase_model)


def test_create_already_existing_fails(full_model):
    _ensure_model_exists(full_model)
    with pytest.raises(exceptions.AlreadyExistsError) as excinfo:
        ml.create_model(model=full_model)
    check_operation_error(
        excinfo,
        'Model \'{0}\' already exists'.format(full_model.display_name))


def test_create_invalid_model(invalid_full_model):
    _delete_if_exists(invalid_full_model)

    firebase_model = ml.create_model(model=invalid_full_model)
    assert firebase_model.display_name == invalid_full_model.display_name
    assert firebase_model.tags == invalid_full_model.tags
    assert firebase_model.model_format.size_bytes is None
    assert firebase_model.model_format.model_source == invalid_full_model.model_format.model_source
    assert firebase_model.model_id is not None
    assert firebase_model.create_time is not None
    assert firebase_model.update_time is not None
    assert firebase_model.validation_error == 'Invalid flatbuffer format'
    assert firebase_model.locked is False
    assert firebase_model.published is False
    assert firebase_model.etag is not None
    assert firebase_model.model_hash is None

    _clean_up_model(firebase_model)

def test_get_model(name_only_model):
    existing_model = _ensure_model_exists(name_only_model)

    firebase_model = ml.get_model(existing_model.model_id)
    assert firebase_model.display_name == name_only_model.display_name
    assert firebase_model.model_id is not None
    assert firebase_model.create_time is not None
    assert firebase_model.update_time is not None
    assert firebase_model.validation_error == 'No model file has been uploaded.'
    assert firebase_model.etag is not None
    assert firebase_model.locked is False
    assert firebase_model.published is False
    assert firebase_model.model_hash is None

    _clean_up_model(firebase_model)


def test_get_non_existing_model(name_only_model):
    # Get a valid model_id that no longer exists
    model = _ensure_model_exists(name_only_model)
    ml.delete_model(model.model_id)

    with pytest.raises(exceptions.NotFoundError) as excinfo:
        ml.get_model(model.model_id)
    check_firebase_error(excinfo, 404, 'Requested entity was not found.')


def test_update_model(name_only_model):
    new_model_name = 'TestModel123_updated'
    _delete_if_exists(ml.Model(display_name=new_model_name))
    existing_model = _ensure_model_exists(name_only_model)
    existing_model.display_name = new_model_name

    firebase_model = ml.update_model(existing_model)
    assert firebase_model.display_name == new_model_name
    assert firebase_model.model_id == existing_model.model_id
    assert firebase_model.create_time == existing_model.create_time
    assert firebase_model.update_time != existing_model.update_time
    assert firebase_model.validation_error == existing_model.validation_error
    assert firebase_model.etag != existing_model.etag
    assert firebase_model.published == existing_model.published
    assert firebase_model.locked == existing_model.locked

    # Second call with same model does not cause error
    firebase_model2 = ml.update_model(firebase_model)
    assert firebase_model2.display_name == firebase_model.display_name
    assert firebase_model2.model_id == firebase_model.model_id
    assert firebase_model2.create_time == firebase_model.create_time
    assert firebase_model2.update_time != firebase_model.update_time
    assert firebase_model2.validation_error == firebase_model.validation_error
    assert firebase_model2.etag != existing_model.etag
    assert firebase_model2.published == firebase_model.published
    assert firebase_model2.locked == firebase_model.locked

    _clean_up_model(firebase_model)


def test_update_non_existing_model(name_only_model):
    model = _ensure_model_exists(name_only_model)
    ml.delete_model(model.model_id)

    model.tags = ['tag987']
    with pytest.raises(exceptions.NotFoundError) as excinfo:
        ml.update_model(model)
    check_operation_error(
        excinfo,
        'Model \'{0}\' was not found'.format(model.as_dict().get('name')))

def test_publish_unpublish_model(full_model):
    model = _ensure_model_exists(full_model)
    assert model.published is False

    published_model = ml.publish_model(model.model_id)
    assert published_model.published is True

    unpublished_model = ml.unpublish_model(published_model.model_id)
    assert unpublished_model.published is False

    _clean_up_model(unpublished_model)


def test_publish_invalid_fails(name_only_model):
    model = _ensure_model_exists(name_only_model)
    assert model.validation_error is not None

    with pytest.raises(exceptions.FailedPreconditionError) as excinfo:
        ml.publish_model(model.model_id)
    check_operation_error(
        excinfo,
        'Cannot publish a model that is not verified.')


def test_publish_unpublish_non_existing_model(full_model):
    model = _ensure_model_exists(full_model)
    ml.delete_model(model.model_id)

    with pytest.raises(exceptions.NotFoundError) as excinfo:
        ml.publish_model(model.model_id)
    check_operation_error(
        excinfo,
        'Model \'{0}\' was not found'.format(model.as_dict().get('name')))

    with pytest.raises(exceptions.NotFoundError) as excinfo:
        ml.unpublish_model(model.model_id)
    check_operation_error(
        excinfo,
        'Model \'{0}\' was not found'.format(model.as_dict().get('name')))


def test_list_models(name_only_model, name_and_tags_model):
    existing_model1 = _ensure_model_exists(name_only_model)
    existing_model2 = _ensure_model_exists(name_and_tags_model)
    filter_str = 'displayName={0} OR tags:{1}'.format(
        existing_model1.display_name, existing_model2.tags[0])

    models_list = ml.list_models(list_filter=filter_str)
    assert len(models_list.models) == 2
    for mdl in models_list.models:
        assert mdl == existing_model1 or mdl == existing_model2
    assert models_list.models[0] != models_list.models[1]

    _clean_up_model(existing_model1)
    _clean_up_model(existing_model2)


def test_list_models_invalid_filter():
    invalid_filter = 'InvalidFilterParam=123'

    with pytest.raises(exceptions.InvalidArgumentError) as excinfo:
        ml.list_models(list_filter=invalid_filter)
    check_firebase_error(excinfo, 400, 'Request contains an invalid argument.')


def test_delete_model(name_only_model):
    existing_model = _ensure_model_exists(name_only_model)

    ml.delete_model(existing_model.model_id)

    # Second delete of same model will fail
    with pytest.raises(exceptions.NotFoundError) as excinfo:
        ml.delete_model(existing_model.model_id)
    check_firebase_error(excinfo, 404, 'Requested entity was not found.')


#'pip install tensorflow' in the environment if you want _TF_ENABLED = True
#'pip install tensorflow=2.0.0' for version 2 etc.
if _TF_ENABLED:
    # Test tensor flow conversion functions if tensor flow is enabled.
    SAVED_MODEL_DIR = '/tmp/saved_model/1'

    def _clean_up_tmp_directory():
        if os.path.exists(SAVED_MODEL_DIR):
            shutil.rmtree(SAVED_MODEL_DIR)

    @pytest.fixture
    def keras_model():
        x_array = [-1, 0, 1, 2, 3, 4]
        y_array = [-3, -1, 1, 3, 5, 7]
        model = tf.keras.models.Sequential(
            [tf.keras.layers.Dense(units=1, input_shape=[1])])
        model.compile(optimizer='sgd', loss='mean_squared_error')
        model.fit(x_array, y_array, epochs=3)
        yield model

    @pytest.fixture
    def saved_model_dir(keras_model):
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


    def test_from_keras_model(keras_model):
        source1 = ml.TFLiteGCSModelSource.from_keras_model(keras_model, 'model2.tflite')
        assert re.search(
            '^gs://.*/Firebase/ML/Models/model2.tflite$',
            source1.gcs_tflite_uri) is not None

        # Validate the conversion by creating a model
        format1 = ml.TFLiteFormat(model_source=source1)
        model1 = ml.Model(display_name="KerasModel1", model_format=format1)
        firebase_model = ml.create_model(model1)
        assert firebase_model.model_id is not None
        assert firebase_model.validation_error is None

        _clean_up_model(firebase_model)

    def test_from_saved_model(saved_model_dir):
        # Test the conversion helper
        source1 = ml.TFLiteGCSModelSource.from_saved_model(saved_model_dir, 'model3.tflite')
        assert re.search(
            '^gs://.*/Firebase/ML/Models/model3.tflite$',
            source1.gcs_tflite_uri) is not None

        # Validate the conversion by creating a model
        format1 = ml.TFLiteFormat(model_source=source1)
        model1 = ml.Model(display_name="SavedModel1", model_format=format1)
        firebase_model = ml.create_model(model1)
        assert firebase_model.model_id is not None
        assert firebase_model.validation_error is None

        _clean_up_model(firebase_model)
        _clean_up_tmp_directory()
