import React, { useState } from 'react';

import { Button, Form, Input, Modal, Select } from 'antd';
import PropTypes from 'prop-types';

import notify from 'ui/helpers/notify';
import { FilterType } from 'ui/maps/Filters';
import API from 'ui/services/API';

export const CreateModal = ({ onSuccess }) => {
  const [form] = Form.useForm();
  const [open, setOpen] = useState(false);
  const handleOpen = () => {
    setOpen(true);
  };
  const handleClose = () => {
    setOpen(false);
  };

  const [submitLoading, setSubmitLoading] = useState(false);

  const handleCreateThreat = async () => {
    setSubmitLoading(true);

    try {
      const values = await form.validateFields();
      const payload = {
        ...values,
        entities: values.entities.map(entity => ({ name: entity })),
      };
      const response = await API.createDeeplink(payload);
      if (response.ok) {
        onSuccess();
        notify('Link template created');
        handleClose();
      } else {
        notify('Failed to create link template');
      }
    } catch (error) {
      notify('Error creating link template', error);
    } finally {
      setSubmitLoading(false);
    }
  };

  return (
    <>
      <Button onClick={handleOpen} type="primary">
        Create Template
      </Button>
      <Modal
        open={open}
        title="Create new template"
        okButtonProps={{ loading: submitLoading }}
        okText={submitLoading ? 'Saving...' : 'Confirm'}
        cancelText="Cancel"
        onOk={handleCreateThreat}
        onCancel={handleClose}
      >
        <Form form={form} layout="vertical" autoComplete="off">
          <Form.Item label="Name" name="name">
            <Input type="text" placeholder="Google" />
          </Form.Item>
          <Form.Item label="Entities" name="entities">
            <Select options={Object.values(FilterType).map(type => ({ value: type }))} mode="multiple" />
          </Form.Item>
          <Form.Item label="Template" name="template">
            <Input type="text" placeholder="https://www.google.com/search?q={{ value }}" />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
};

CreateModal.propTypes = {
  onSuccess: PropTypes.func,
};
