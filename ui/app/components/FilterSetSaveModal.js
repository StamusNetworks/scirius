import React from 'react';
import PropTypes from 'prop-types';
import { Button, Checkbox, Col, Form, Input, Modal, Row, Select } from 'antd';
import { huntTabs } from 'constants';
import HuntRestError from './HuntRestError';

const FilterSetSaveModal = (props) => (
  <Modal
    title={props.title}
    visible={props.showModal}
    onCancel={props.close}
    footer={
      <React.Fragment>
        <Button bsStyle="default" className="btn-cancel" onClick={props.close}>
          Cancel
        </Button>
        <Button bsStyle="primary" onClick={props.submit}>
          Save
        </Button>
      </React.Fragment>
    }
  >
    <div
      onClick={
        // Stopping event propagation is required since the modal is the children of a list item that
        // will also react to clicks
        (e) => {
          e.stopPropagation();
        }
      }
    >
      <HuntRestError errors={props.errors} />
      <Form>
        <Row>
          <Col span={6}>
            <strong>Name</strong>
          </Col>
          <Col span={18}>
            <Form.Item name="input-name">
              <Input
                defaultValue=""
                onChange={props.handleFieldChange}
                onKeyDown={(e) => {
                  if (e.keyCode === 13) {
                    e.preventDefault();
                    props.submit();
                  }
                }}
                style={{ width: '100%' }}
              />
            </Form.Item>
          </Col>
        </Row>
        <Row>
          <Col span={6}>
            <strong>Page</strong>
          </Col>
          <Col span={18}>
            {!props.page && (
              <Form.Item name="select-page">
                <Select style={{ width: '100%' }} placeholder="Please select page" onChange={props.handleComboChange}>
                  {Object.keys(huntTabs).filter((key) => huntTabs[key] !== 'Policies').map((key) => (
                    <Select.Option key={huntTabs[key]} value={key}>
                      {huntTabs[key]}
                    </Select.Option> // eslint-disable-line indent
                  ))}
                </Select>
              </Form.Item>
            )}
            {props.page && <Input disabled defaultValue={props.page} />}
          </Col>
        </Row>
        {!props.noRights && (
          <Row>
            <Col span={6}>
              <Form.Item name="checkbox">
                <Checkbox onChange={props.setSharedFilter}>
                  <strong>Shared</strong>
                </Checkbox>
              </Form.Item>
            </Col>
            <Col span={18}>
              <span
                className="pficon-help"
                data-toggle="tooltip"
                title="Enable: Create Filter Set with All Users&#10;Disable: Create Filter Set only for you"
              />
            </Col>
          </Row>
        )}
        <Row>
          <Col span={6}>
            <strong>Description:</strong>
          </Col>
          <Col span={18}>
            <Form.Item name="textarea-description">
              <Input.TextArea onChange={props.handleDescriptionChange} />
            </Form.Item>
          </Col>
        </Row>
      </Form>
    </div>
  </Modal>
);

FilterSetSaveModal.propTypes = {
  title: PropTypes.any,
  showModal: PropTypes.any,
  close: PropTypes.any,
  errors: PropTypes.any,
  handleDescriptionChange: PropTypes.any,
  handleComboChange: PropTypes.any,
  handleFieldChange: PropTypes.any,
  setSharedFilter: PropTypes.any,
  submit: PropTypes.any,
  page: PropTypes.any,
  noRights: PropTypes.bool.isRequired,
};

export default FilterSetSaveModal;
