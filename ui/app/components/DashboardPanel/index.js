import React, { useEffect, useState } from 'react';

import PropTypes from 'prop-types';
import styled from 'styled-components';

import DashboardBlock from 'ui/components/DashboardBlock';
import DashboardBlockMore from 'ui/components/DashboardBlockMore';
import endpoints from 'ui/config/endpoints';
import dashboardSanitizer from 'ui/helpers/dashboardSanitizer';
import useAutorun from 'ui/helpers/useAutorun';
import { api } from 'ui/mobx/api';

const Title = styled.h2`
  margin: 0.5rem 0;
  cursor: default;
`;

const Row = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(${({ itemsMinWidth }) => itemsMinWidth || '250px'}, 1fr));
  grid-gap: 5px;
  padding-bottom: 10px;
`;

const DashboardPanel = ({ panel, hideEmptyTiles, setPanelIsEmpty }) => {
  /* Load more stuff */
  const [loadMoreField, setLoadMoreField] = useState({ block: null, field: null });
  const [loadMoreVisible, setLoadMoreVisible] = useState(false);
  const [loadMoreData, setLoadMoreData] = useState({});

  /* Dashboard blocks stuff */
  const [loading, setLoading] = useState(true);
  const [blockData, setBlockData] = useState({});
  const { title, items } = panel;
  const emptyPanel = Object.values(blockData).every(block => block?.length === 0);

  const fetchData = async (fields, pageSize) => {
    const response = await api.get(endpoints.DASHBOARD_PANEL.url, {
      fields,
      page_size: pageSize,
    });
    return response.data;
  };

  const fields = panel.items.map(item => item.i).join(',');

  useAutorun(async () => {
    const data = await fetchData(fields, 5);
    setLoading(false);
    setBlockData(dashboardSanitizer(data));
    setPanelIsEmpty(
      panel.panelId,
      Object.values(data).every(block => block?.length === 0),
    );
  }, [fields]);

  useEffect(() => {
    if (loadMoreField.field) {
      (async () => {
        const data = await fetchData(loadMoreField.field, 30);
        setLoadMoreData(dashboardSanitizer(data));
        setLoadMoreVisible(true);
      })();
    }
  }, [loadMoreField.field]);

  if (hideEmptyTiles && emptyPanel) return null;

  return (
    <div data-test={`dashboard-panel-${title}`}>
      <Title>{title}</Title>
      <Row itemsMinWidth={panel.itemsMinWidth}>
        {items.map(item => {
          const { [item.i]: data = [] } = blockData || {};
          if (hideEmptyTiles && data.length === 0) return null;
          return (
            <DashboardBlock
              key={item.i}
              block={item}
              data={data}
              loading={loading}
              emptyPanel={emptyPanel}
              onLoadMore={() => setLoadMoreField({ block: item, field: item.i })}
            />
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

export default DashboardPanel;

DashboardPanel.propTypes = {
  panel: PropTypes.string,
  hideEmptyTiles: PropTypes.bool,
  setPanelIsEmpty: PropTypes.func,
};
