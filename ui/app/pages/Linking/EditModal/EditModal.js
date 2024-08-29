import React, { useState } from 'react';

import { EditOutlined } from '@ant-design/icons';
import { Button, Form, Input, Modal, Select } from 'antd';
import PropTypes from 'prop-types';

import { FilterType } from 'ui/maps/Filters';

export const EditModal = ({ initialValues }) => {
  const [open, setOpen] = useState(false);
  const handleOpen = () => {
    setOpen(true);
  };
  const handleClose = () => {
    setOpen(false);
  };

  const [deleteLoading, setDeleteLoading] = useState(false);

  const handleDeleteThreat = async () => {
    setDeleteLoading(true);
  };

  return (
    <>
      <Button onClick={handleOpen} icon={<EditOutlined />} />
      <Modal
        open={open}
        title="Edit this template"
        okButtonProps={{ loading: deleteLoading }}
        okText={deleteLoading ? 'Saving...' : 'Confirm'}
        cancelText="Cancel"
        onOk={handleDeleteThreat}
        onCancel={handleClose}
      >
        <Form layout="vertical" autoComplete="off" initialValues={initialValues}>
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

EditModal.propTypes = {
  initialValues: PropTypes.object,
};
