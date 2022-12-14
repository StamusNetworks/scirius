import React, { useEffect } from 'react';
import PropTypes from 'prop-types';
import { useDispatch, useSelector } from 'react-redux';
import { Modal } from 'antd';
import { dashboard } from 'ui/config/Dashboard';
import dashboardSelectors from 'ui/stores/dashboard/selectors';
import dashboardActions from 'ui/stores/dashboard/actions';
import DashboardBlock from 'ui/components/DashboardBlock';

const DashboardBlockMore = ({ visible, onClose, panelId, blockId }) => {
  const dispatch = useDispatch();
  useEffect(() => {
    if (visible) {
      dispatch(dashboardActions.getBlockMoreResultsRequest(blockId));
    }
  }, [visible]);

  const { data = [], loading } = useSelector(dashboardSelectors.makeSelectMoreResults());
  const { [panelId]: panel = [] } = dashboard;
  const { items = [] } = panel;
  const block = items.find(item => item.i === blockId);
  return (
    <Modal title="More results" footer={null} visible={visible} onCancel={onClose} bodyStyle={{ padding: 0 }} data-test="load-more-modal">
      <DashboardBlock block={block} data={data} loading={loading} />
    </Modal>
  );
};

export default DashboardBlockMore;

DashboardBlockMore.propTypes = {
  visible: PropTypes.bool.isRequired,
  onClose: PropTypes.func.isRequired,
  blockId: PropTypes.string,
  panelId: PropTypes.string,
};
