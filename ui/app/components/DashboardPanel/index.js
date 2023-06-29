import React, { useCallback, useEffect, useState } from 'react';
import PropTypes from 'prop-types';
import styled from 'styled-components';
import { Col, Row } from 'antd';
import { dashboard } from 'ui/config/Dashboard';
import DashboardBlock from 'ui/components/DashboardBlock';
import { useStore } from 'ui/mobx/RootStoreProvider';
import useAutorun from 'ui/helpers/useAutorun';
import { buildQFilter } from 'ui/buildQFilter';
import endpoints from 'ui/config/endpoints';
import dashboardSanitizer from 'ui/helpers/dashboardSanitizer';
import DashboardBlockMore from 'ui/components/DashboardBlockMore';
import { observer } from 'mobx-react-lite';
import { api } from '../../mobx/api';

const Title = styled.h2`
  margin-top: 10px;
  cursor: default;
`;

const DashboardPanel = ({ panelId }) => {
  /* Load more stuff */
  const [loadMoreField, setLoadMoreField] = useState({ block: null, field: null });
  const [loadMoreVisible, setLoadMoreVisible] = useState(false);
  const [loadMoreData, setLoadMoreData] = useState({});

  /* Dashboard blocks stuff */
  const [loading, setLoading] = useState(true);
  const [blockData, setBlockData] = useState({});
  const { title, items } = dashboard[panelId];
  const emptyPanel = Object.values(blockData).every(block => block?.length === 0);
  const { commonStore } = useStore();

  const fetchData = useCallback(
    async (fields, pageSize) => {
      const qfilter = (buildQFilter(commonStore.filtersWithAlert, commonStore.systemSettings) || '').replace('&qfilter=', '');
      const response = await api.get(endpoints.DASHBOARD_PANEL.url, {
        fields,
        qfilter: decodeURIComponent(qfilter),
        page_size: pageSize,
      });
      return response.data;
    },
    [commonStore.filtersWithAlert, commonStore.systemSettings],
  );

  useAutorun(async () => {
    setLoading(true);
    const fields = dashboard[panelId].items.map(item => item.i).join(',');
    const data = await fetchData(fields, 5);
    setBlockData(dashboardSanitizer(data));
    setLoading(false);
  });

  useEffect(() => {
    if (loadMoreField.field) {
      (async () => {
        const data = await fetchData(loadMoreField.field, 30);
        setLoadMoreData(dashboardSanitizer(data));
        setLoadMoreVisible(true);
      })();
    }
  }, [loadMoreField.field]);

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
                onLoadMore={() => setLoadMoreField({ block: item, field: item.i })}
              />
            </Col>
          );
        })}
      </Row>
      {loadMoreVisible && (
        <DashboardBlockMore
          data={loadMoreData[loadMoreField.field] || []}
          block={loadMoreField.block}
          onClose={() => {
            setLoadMoreVisible(false);
            setLoadMoreField({ block: null, field: null });
          }}
        />
      )}
    </div>
  );
};

export default observer(DashboardPanel);

DashboardPanel.propTypes = {
  panelId: PropTypes.string,
};
