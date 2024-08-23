import React, { useState } from 'react';

import { Button, Form, Input, Modal, Select } from 'antd';

export const CreateModal = () => {
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
      <Button onClick={handleOpen} type="primary">
        Create Template
      </Button>
      <Modal
        open={open}
        title="Create new template"
        okButtonProps={{ loading: deleteLoading }}
        okText={deleteLoading ? 'Saving...' : 'Confirm'}
        cancelText="Cancel"
        onOk={handleDeleteThreat}
        onCancel={handleClose}
      >
        <Form layout="vertical" autoComplete="off">
          <Form.Item label="Label" name="label">
            <Input type="text" placeholder="Google" />
          </Form.Item>
          <Form.Item label="Entity" name="entity">
            <Select options={[{ value: 'IP' }, { value: 'Threat' }, { value: 'Signature ID' }]} mode="multiple" />
          </Form.Item>
          <Form.Item label="Template" name="template">
            <Input type="text" placeholder="https://www.google.com/search?q={{ value }}" />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
};
