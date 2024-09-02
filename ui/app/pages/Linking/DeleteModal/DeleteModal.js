import React, { useState } from 'react';

import { ExclamationCircleOutlined, DeleteOutlined } from '@ant-design/icons';
import { Button, Modal } from 'antd';
import PropTypes from 'prop-types';

import API from 'ui/services/API';

import * as Style from './style';

export const DeleteModal = ({ pk, onSuccess }) => {
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
    await API.deleteDeeplink(pk);
    onSuccess();
    handleClose();
  };

  return (
    <>
      <Button onClick={handleOpen} icon={<DeleteOutlined />} danger />
      <Modal
        open={open}
        title="Delete this template"
        okButtonProps={{ danger: true, loading: deleteLoading }}
        okText={deleteLoading ? 'Deleting...' : 'Confirm'}
        cancelText="Cancel"
        onOk={handleDeleteThreat}
        onCancel={handleClose}
      >
        <Style.Content>
          <ExclamationCircleOutlined />
          <div>Are you sure you want to delete this template? You will not be able to recover it.</div>
        </Style.Content>
      </Modal>
    </>
  );
};

DeleteModal.propTypes = {
  pk: PropTypes.number.isRequired,
  onSuccess: PropTypes.func.isRequired,
};
