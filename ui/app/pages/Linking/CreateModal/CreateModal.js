import React, { useState } from 'react';

import { EditOutlined } from '@ant-design/icons';
import { Button, Form, Input, Modal, Radio, Select } from 'antd';
import PropTypes from 'prop-types';

import notify from 'ui/helpers/notify';
import { FilterType } from 'ui/maps/Filters';
import API from 'ui/services/API';

const emptyForm = {
  name: '',
  entities: [],
  template: '',
  all: true,
};

const allOptions = [
  {
    label: 'Always show template',
    value: true,
  },
  {
    label: 'Only show template for selected entities',
    value: false,
  },
];

const filterTypeOptions = Object.values(FilterType).map(type => ({ value: type }));

export const CreateModal = ({ initialValues, onSuccess }) => {
  const isCreate = initialValues === undefined;
  const action = isCreate ? 'create' : 'update';
  const [form] = Form.useForm();
  const isAllEntities = Form.useWatch('all', form);
  const [open, setOpen] = useState(false);
  const handleOpen = () => {
    setOpen(true);
  };
  const handleClose = () => {
    setOpen(false);
  };

  const [submitLoading, setSubmitLoading] = useState(false);

  const handleSubmitThreat = async () => {
    setSubmitLoading(true);

    try {
      const values = await form.validateFields();
      const payload = {
        ...values,
        entities: values.entities.map(entity => ({ name: entity })),
      };
      const response = isCreate ? await API.createDeeplink(payload) : await API.updateDeeplink(initialValues.pk, { body: payload });
      if (response.ok) {
        onSuccess();
        notify(`Link template ${action}d`);
        handleClose();
      } else {
        notify(`Failed to ${action} link template`);
      }
    } catch (error) {
      notify(`Error ${action.slice(0, -1)}ing link template`, error);
    } finally {
      setSubmitLoading(false);
    }
  };

  return (
    <>
      {isCreate ? (
        <Button onClick={handleOpen} type="primary">
          Create Template
        </Button>
      ) : (
        <Button onClick={handleOpen} icon={<EditOutlined />} />
      )}
      <Modal
        open={open}
        title={isCreate ? 'Create new template' : 'Edit template'}
        okButtonProps={{ loading: submitLoading }}
        okText={submitLoading ? 'Saving...' : 'Submit'}
        cancelText="Cancel"
        onOk={handleSubmitThreat}
        onCancel={handleClose}
      >
        <Form form={form} layout="vertical" autoComplete="off" initialValues={initialValues || emptyForm}>
          <Form.Item label="Name" name="name">
            <Input type="text" placeholder="Google" />
          </Form.Item>
          <Form.Item label="Template" name="template">
            <Input type="text" placeholder="https://www.google.com/search?q={{ value }}" />
          </Form.Item>
          <Form.Item name="all" layout="horizontal" style={{ marginBottom: '0.25rem' }}>
            <Radio.Group options={allOptions} />
          </Form.Item>
          <Form.Item name="entities">
            <Select options={filterTypeOptions} mode="multiple" disabled={isAllEntities} />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
};

CreateModal.propTypes = {
  onSuccess: PropTypes.func.isRequired,
  initialValues: PropTypes.shape({
    pk: PropTypes.number.isRequired,
    name: PropTypes.string.isRequired,
    entities: PropTypes.arrayOf(PropTypes.string).isRequired,
    template: PropTypes.string.isRequired,
    all: PropTypes.bool.isRequired,
  }),
};
