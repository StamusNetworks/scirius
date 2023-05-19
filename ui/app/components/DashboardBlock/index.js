import React, { useEffect, useState } from 'react';
import PropTypes from 'prop-types';
import { Dropdown, Empty, Menu } from 'antd';
import { LoadingOutlined, MenuOutlined } from '@ant-design/icons';
import { useSelector } from 'react-redux';
import UICard from 'ui/components/UIElements/UICard';
import { COLOR_BRAND_BLUE } from 'ui/constants/colors';
import DashboardBlockData from 'ui/components/DashboardBlockData';
import dashboardSelectors from 'ui/stores/dashboard/selectors';
import styled from 'styled-components';

const Title = styled.div`
  text-align: center;
  cursor: default;
`;

const DashboardBlock = ({ block, data, loading, onLoadMore, onDownload, emptyPanel }) => {
  const copyMode = useSelector(dashboardSelectors.makeSelectCopyMode());

  const [loadingVisible, setLoadingVisible] = useState(false);

  // Loading flag debounce
  useEffect(() => {
    setTimeout(() => setLoadingVisible(loading), loading ? 0 : 500);
  }, [loading]);

  const menu = (
    <Menu>
      {onLoadMore && (
        <Menu.Item key="load-more" onClick={onLoadMore} data-toggle="modal">
          Load more results
        </Menu.Item>
      )}
      {onDownload && (
        <Menu.Item key="download-data" onClick={onDownload} data-toggle="modal">
          Download
        </Menu.Item>
      )}
    </Menu>
  );

  return (
    <UICard
      flex
      data-test={`dashboard-block-${block.title}`}
      title={block.title && <Title>{block.title}</Title>}
      extra={
        <>
          {loadingVisible && <LoadingOutlined data-test="loading" />}
          {!loadingVisible && data?.length > 0 && (onLoadMore || onDownload) && (
            <Dropdown overlay={menu} trigger={['click']}>
              <a className="ant-dropdown-link" style={{ color: COLOR_BRAND_BLUE }} onClick={e => e.preventDefault()}>
                <MenuOutlined />
              </a>
            </Dropdown>
          )}
        </>
      }
      bodyStyle={emptyPanel ? { display: 'none' } : {}}
    >
      {!loading && data.length === 0 && !emptyPanel && <Empty style={{ margin: '20px 0' }} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
      <DashboardBlockData block={block} data={data} copyMode={copyMode} />
    </UICard>
  );
};

export default React.memo(
  DashboardBlock,
  (prevProps, nextProps) =>
    !(prevProps.block.i !== nextProps.block.i || prevProps.block.title !== nextProps.block.title || prevProps.loading !== nextProps.loading),
);

DashboardBlock.propTypes = {
  block: PropTypes.shape({
    i: PropTypes.string,
    title: PropTypes.string,
    format: PropTypes.func,
    dimensions: PropTypes.shape({
      xxl: PropTypes.number,
      xl: PropTypes.number,
    }),
  }),
  title: PropTypes.string,
  data: PropTypes.array,
  loading: PropTypes.bool,
  onLoadMore: PropTypes.func,
  onDownload: PropTypes.func,
  emptyPanel: PropTypes.bool,
};
