import React, { useState, useEffect } from 'react';

import { Modal } from 'antd';
import PropTypes from 'prop-types';

import DashboardBlock from 'ui/components/DashboardBlock';

const DashboardBlockMore = ({ loading, data, onClose, block }) => {
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    setVisible(true);
  }, []);

  return (
    <Modal
      title="More results"
      footer={null}
      open={visible}
      onCancel={() => {
        setVisible(false);
      }}
      afterClose={onClose}
      bodyStyle={{ padding: 0 }}
      data-test="load-more-modal"
    >
      <DashboardBlock block={block} data={data} loading={loading} />
    </Modal>
  );
};

export default DashboardBlockMore;

DashboardBlockMore.propTypes = {
  data: PropTypes.any,
  onClose: PropTypes.func.isRequired,
  block: PropTypes.object,
  loading: PropTypes.bool,
};
