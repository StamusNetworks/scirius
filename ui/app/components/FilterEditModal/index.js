import React, { useEffect, useState } from 'react';

import { InfoCircleOutlined } from '@ant-design/icons';
import { Button, Checkbox, Form, Input, Modal, Space } from 'antd';
import PropTypes from 'prop-types';
import styled from 'styled-components';

import isNumeric from 'ui/helpers/isNumeric';
import Filter from 'ui/utils/Filter';

import FilterValueType from '../../maps/FilterValueType';

const ModalHuntFilter = styled(Modal)`
  & .modal-body {
    padding-bottom: 0;
  }
  & .modal-footer {
    margin-top: 0;
  }
`;

const FormFooter = styled(Space)`
  justify-content: end;
  width: 100%;
`;

const FilterEditModal = ({ onClose, filter }) => {
  const [form] = Form.useForm();
  const [helperText, setHelperText] = useState();
  const [disabled, setDisabled] = useState(false);

  useEffect(() => {
    form.setFieldsValue({
      value: filter.value,
      negated: filter.negated,
      // Prevents checking the wildcard checkbox when filter schema has { defaults: { wildcard: true } }
      wildcard: filter.wildcardable && !filter.fullString,
    });
    setHelperText(getHelperText());
  }, [form, filter]);

  const onFinish = values => {
    filter.value = isNumeric(values.value) ? parseInt(values.value, 10) : values.value;
    filter.fullString = !values.wildcard;
    filter.negated = values.negated;
    onClose();
  };

  const getHelperText = () => {
    let result = '';
    if (['msg', 'not_in_msg', 'content', 'not_in_content'].includes(filter.id)) {
      result = <div>Case insensitive substring match.</div>;
    } else if (['hits_min', 'hits_max'].includes(filter.id)) {
      result = <div></div>;
    } else if (['es_filter'].includes(filter.id)) {
      result = <div>Free ES filter with Lucene syntax</div>;
    } else if (form.getFieldValue('wildcard') && filter.wildcardable) {
      result = (
        <div>
          Wildcard characters (<i style={{ padding: '0px 5px', background: '#e0e0e0', margin: '0 2px' }}>*</i> and{' '}
          <i style={{ padding: '0px 5px', background: '#e0e0e0', margin: '0 2px' }}>?</i>) can match on word boundaries.
          <br />
          No spaces allowed.
        </div>
      );
    } else {
      result = <div>Exact match</div>;
    }
    return result;
  };

  return (
    <ModalHuntFilter width={650} footer={false} title="Edit filter" visible onCancel={() => onClose()} className="modal-hunt-filter">
      <Form
        form={form}
        labelCol={{ span: 6 }}
        name="filter-edit"
        onFinish={onFinish}
        onValuesChange={() => {
          setHelperText(getHelperText());
        }}
      >
        <Form.Item
          name="value"
          label="Filter"
          extra={helperText}
          shouldUpdate
          dependencies={['wildcard']}
          hasFeedback
          required
          rules={[
            ({ getFieldValue }) => ({
              validator: () => {
                // validation by length
                if (getFieldValue('value').length === 0) {
                  setDisabled(true);
                  return Promise.reject(new Error('Filter value must not be empty'));
                }
                // validation by type
                if (filter.schema?.valueType) {
                  switch (filter.schema?.valueType) {
                    case FilterValueType.NUMBER: {
                      if (!isNumeric(getFieldValue('value'))) {
                        setDisabled(true);
                        return Promise.reject(new Error('Filter value must be number'));
                      }
                      break;
                    }
                    default:
                      break;
                  }
                }
                // validation by wildcardable
                if (getFieldValue('wildcard') && getFieldValue('value').match(/[\s]+/g)) {
                  setDisabled(true);
                  return Promise.reject(new Error('No spaces allowed.'));
                }
                setDisabled(false);
                return Promise.resolve();
              },
            }),
          ]}
        >
          <Input addonBefore={filter.id} data-test="edit-filter-input-field" id="input-value-filter" style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item
          name="wildcard"
          label="Wildcard view"
          valuePropName="checked"
          help={
            !filter.wildcardable && (
              <Space>
                <InfoCircleOutlined />
                <span data-test="wildcard-disabled">Filter {filter.id} cannot use wildcards</span>
              </Space>
            )
          }
        >
          <Checkbox data-test="wildcard-checkbox" disabled={!filter.wildcardable} />
        </Form.Item>
        <Form.Item
          name="negated"
          label="Negated"
          valuePropName="checked"
          help={
            !filter.negatable && (
              <Space>
                <InfoCircleOutlined />
                <span data-test="negated-disabled">Filter {filter.id} cannot be negated</span>
              </Space>
            )
          }
        >
          <Checkbox data-test="negated-filter-checkbox" disabled={!filter.negatable} />
        </Form.Item>
        <Form.Item noStyle>
          <FormFooter>
            <Button data-test="cancel-edit-filter-button" onClick={onClose}>
              Cancel
            </Button>
            <Button data-test="save-edit-filter-button" type="primary" htmlType="submit" disabled={disabled}>
              Save
            </Button>
          </FormFooter>
        </Form.Item>
      </Form>
    </ModalHuntFilter>
  );
};

export default FilterEditModal;

FilterEditModal.propTypes = {
  filter: PropTypes.instanceOf(Filter),
  onClose: PropTypes.func,
};
