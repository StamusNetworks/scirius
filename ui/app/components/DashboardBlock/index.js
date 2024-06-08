import React, { useContext, useEffect, useState } from 'react';

import { LoadingOutlined, MenuOutlined } from '@ant-design/icons';
import { Dropdown, Empty, Menu, message } from 'antd';
import { isEqual } from 'lodash';
import PropTypes from 'prop-types';
import styled from 'styled-components';

import DashboardBlockData from 'ui/components/DashboardBlockData';
import UICard from 'ui/components/UIElements/UICard';
import { COLOR_BRAND_BLUE } from 'ui/constants/colors';
import DashboardContext from 'ui/context/DashboardContext';
import downloadData from 'ui/helpers/downloadData';

const Title = styled.div`
  text-align: center;
  cursor: default;
`;

const DashboardBlock = ({ block, data, loading, onLoadMore, emptyPanel }) => {
  const copyMode = useContext(DashboardContext);
  const [loadingVisible, setLoadingVisible] = useState(false);

  // Loading flag debounce
  useEffect(() => {
    setTimeout(() => setLoadingVisible(loading), loading ? 0 : 500);
  }, [loading]);

  const onDownload = async () => {
    message.success(`Downloading ${block.title}`);
    await downloadData.text(data.map(o => o.key).join('\n'), block.title.toLowerCase());
  };

  const menu = (
    <Menu>
      {onLoadMore && (
        <Menu.Item key="load-more" data-test="load-more-results" onClick={onLoadMore} data-toggle="modal">
          Load more results
        </Menu.Item>
      )}
      <Menu.Item key="download-data" data-test="download-data" onClick={onDownload} data-toggle="modal">
        Download
      </Menu.Item>
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
          {!loadingVisible && data?.length > 0 && (
            <Dropdown overlay={menu} trigger={['click']}>
              <a className="ant-dropdown-link" data-test="menu" style={{ color: COLOR_BRAND_BLUE }} onClick={e => e.preventDefault()}>
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
  (prevProps, nextProps) => isEqual(prevProps.data, nextProps.data) && prevProps.loading === nextProps.loading,
);

DashboardBlock.propTypes = {
  block: PropTypes.shape({
    i: PropTypes.string,
    title: PropTypes.string,
    format: PropTypes.func,
  }),
  title: PropTypes.string,
  data: PropTypes.array,
  loading: PropTypes.bool,
  onLoadMore: PropTypes.func,
  emptyPanel: PropTypes.bool,
};
