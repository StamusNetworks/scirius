import React from 'react';
import PropTypes from 'prop-types';
import styled from 'styled-components';
import { Col, message, Row } from 'antd';
import { useDispatch } from 'react-redux';
import { dashboard } from 'ui/config/Dashboard';
import actions from 'ui/stores/dashboard/actions';
import DashboardBlock from 'ui/components/DashboardBlock';

const Title = styled.h2`
  margin-top: 10px;
  cursor: default;
`;

const DashboardPanel = ({ panelId, blocks, loading }) => {
  const dispatch = useDispatch();
  const { title, items } = dashboard[panelId];
  const emptyPanel = blocks && Object.values(blocks).every(block => block?.length === 0);
  return (
    <div data-test={`dashboard-panel-${title}`}>
      <Title>{title}</Title>
      <Row gutter={[5, 5]}>
        {items.map(item => {
          const { [item.i]: data = [] } = blocks || {};
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
export default React.memo(
  DashboardPanel,
  (prevProps, nextProps) => !(prevProps.panelId !== nextProps.panelId || prevProps.loading !== nextProps.loading),
);

DashboardPanel.propTypes = {
  panelId: PropTypes.string,
  blocks: PropTypes.object,
  loading: PropTypes.bool,
};
