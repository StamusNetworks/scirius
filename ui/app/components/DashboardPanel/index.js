import React, { createRef, useState } from 'react';
import PropTypes from 'prop-types';
import styled from 'styled-components';
import { Col, message, Row } from 'antd';
import { useDispatch } from 'react-redux';
import { dashboard } from 'ui/config/Dashboard';
import actions from 'ui/stores/dashboard/actions';
import DashboardBlock from 'ui/components/DashboardBlock';
import { useStore } from 'ui/mobx/RootStoreProvider';
import useAutorun from 'ui/helpers/useAutorun';
import { buildQFilter } from 'ui/buildQFilter';
import endpoints from 'ui/config/endpoints';
import { toJS } from 'mobx';
import { observer } from 'mobx-react-lite';
import { api } from '../../mobx/api';

const Title = styled.h2`
  margin-top: 10px;
  cursor: default;
`;

const dashboardSanitizer = data => {
  /**
   * Convert empty keys to 'Unknown' values
   */
  const blockIds = Object.keys(data);
  if (blockIds.length > 0) {
    blockIds.forEach(blockId => {
      for (let idx = 0; idx < data[blockId].length; idx += 1) {
        data.nodeRef = createRef(null);
        if (!data[blockId][idx].key) {
          data[blockId][idx].key = 'Unknown';
        }
      }
    });
  }
  return data;
};

const DashboardPanel = ({ panelId }) => {
  const dispatch = useDispatch();
  const [loading, setLoading] = useState(true);
  const [blockData, setBlockData] = useState({});
  const { title, items } = dashboard[panelId];
  const emptyPanel = Object.values(blockData).every(block => block?.length === 0);
  const { commonStore } = useStore();

  useAutorun(async () => {
    setLoading(true);
    const fields = dashboard[panelId].items.map(item => item.i).join(',');
    const qfilter = (buildQFilter(commonStore.getFilters(true), toJS(commonStore.systemSettings)) || '').replace('&qfilter=', '');
    const response = await api.get(endpoints.DASHBOARD_PANEL.url, {
      fields,
      qfilter,
      page_size: 5,
    });
    setBlockData(dashboardSanitizer(response.data));
    setLoading(false);
  });

  return (
    <div data-test={`dashboard-panel-${title}`}>
      <Title>{title}</Title>
      <Row gutter={[5, 5]}>
        {items.map(item => {
          const { [item.i]: data = [] } = blockData || {};
          const {
            dimensions: { xxl, xl },
          } = item;
          return (
            <Col xxl={xxl} xl={xl} lg={12} md={24} xs={24} style={{ display: 'flex' }}>
              <DashboardBlock
                block={item}
                data={data}
                loading={loading}
                emptyPanel={emptyPanel}
                onLoadMore={() => dispatch(actions.setModalMoreResults(true, panelId, item.i))}
                onDownload={() => {
                  message.success(`Downloading ${item.title}`);
                  dispatch(actions.downloadBlockData(item.i, item.title.toLowerCase()));
                }}
              />
            </Col>
          );
        })}
      </Row>
    </div>
  );
};

export default observer(DashboardPanel);

DashboardPanel.propTypes = {
  panelId: PropTypes.string,
};
