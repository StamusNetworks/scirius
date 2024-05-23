import React, { useState, useEffect, useCallback } from 'react';

import { Button, Col, Form, Input, InputNumber, Modal, Row } from 'antd';
import axios from 'axios';
import PropTypes from 'prop-types';

import * as config from 'config/Api';
import HuntRestError from 'ui/components/HuntRestError';

const FilterToggleModal = ({ action, lastIndex, data, show, close, needUpdate }) => {
  const [comment, setComment] = useState('');
  const [newIndex, setNewIndex] = useState(0);
  const [errors, setErrors] = useState(undefined);

  useEffect(() => {
    setNewIndex(action === 'movebottom' ? lastIndex : 0);
  }, [action, lastIndex]);

  const closeHandler = useCallback(() => {
    setErrors(undefined);
    close();
  }, [close]);

  const submitHandler = useCallback(() => {
    let requestData;
    if (['move', 'movetop', 'movebottom'].includes(action)) {
      requestData = { index: newIndex, comment };
      axios
        .patch(`${config.API_URL}${config.PROCESSING_PATH}${data.pk}/`, requestData)
        .then(() => {
          needUpdate();
          closeHandler();
        })
        .catch(error => {
          setErrors(error.response.data);
        });
    }
    if (action === 'delete') {
      requestData = { comment };
      axios({
        url: `${config.API_URL}${config.PROCESSING_PATH}${data.pk}/`,
        data: requestData,
        method: 'delete',
      })
        .then(() => {
          needUpdate();
          closeHandler();
        })
        .catch(error => {
          setErrors(error.response.data);
        });
    }
  }, [action, comment, data, newIndex, needUpdate, closeHandler]);

  const handleChange = useCallback(value => {
    const val = parseInt(value, 10);
    if (val >= 0) {
      setNewIndex(val);
    }
  }, []);

  const handleCommentChange = useCallback(event => {
    setComment(event.target.value);
  }, []);

  const onFieldKeyPress = useCallback(
    keyEvent => {
      if (keyEvent.key === 'Enter' && newIndex >= 0) {
        keyEvent.stopPropagation();
        keyEvent.preventDefault();
      }
    },
    [newIndex],
  );

  const onModalClick = useCallback(e => {
    e.stopPropagation();
  }, []);

  const actionTitle =
    {
      movetop: 'Move to top',
      move: 'Move',
      movebottom: 'Move to bottom',
      delete: 'Delete',
    }[action] || '';

  return (
    <Modal
      title={
        data && (
          <div>
            {actionTitle} {data.action} at current position {data.index}
          </div>
        )
      }
      open={show}
      onCancel={closeHandler}
      footer={
        <>
          <Button className="btn-cancel" onClick={closeHandler} data-test="policies-cancel">
            Cancel
          </Button>
          <Button onClick={submitHandler} data-test="policies-submit">
            Submit
          </Button>
        </>
      }
    >
      <div onClick={onModalClick}>
        <HuntRestError errors={errors} />
        <Form>
          {action === 'move' && (
            <Row>
              <Col span={6}>
                <strong>New index</strong>
              </Col>
              <Col span={18}>
                <Form.Item name="input-number">
                  <InputNumber
                    min={0}
                    max={50000}
                    defaultValue={0}
                    onChange={handleChange}
                    onKeyPress={onFieldKeyPress}
                    style={{ width: '100%' }}
                    data-test="new-index"
                  />
                </Form.Item>
              </Col>
            </Row>
          )}
          <Row>
            <Col md={24}>
              <strong>Optional comment</strong>
            </Col>
            <Col md={24}>
              <Input.TextArea value={comment} onChange={handleCommentChange} />
            </Col>
          </Row>
        </Form>
      </div>
    </Modal>
  );
};

FilterToggleModal.propTypes = {
  action: PropTypes.any,
  lastIndex: PropTypes.any,
  data: PropTypes.any,
  show: PropTypes.any,
  close: PropTypes.func,
  needUpdate: PropTypes.func,
};

export default FilterToggleModal;
