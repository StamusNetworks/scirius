import React from 'react';
import { Space, Card, Tooltip, Button } from 'antd';
import {
  BellOutlined,
  DashboardOutlined,
  IdcardOutlined,
  SafetyOutlined,
  UploadOutlined,
  CaretRightOutlined,
  InfoCircleOutlined,
  DeleteOutlined,
} from '@ant-design/icons';
import PropTypes from 'prop-types';
import styled from 'styled-components';

const getIcons = item => {
  const icons = [];
  if (item.page === 'DASHBOARDS') {
    icons.push(<DashboardOutlined key="0" />);
  }
  if (item.page === 'RULES_LIST') {
    icons.push(<SafetyOutlined key="1" />);
  }
  if (item.page === 'ALERTS_LIST') {
    icons.push(<BellOutlined key="2" />);
  }
  if (item.page === 'HOSTS_LIST') {
    icons.push(<IdcardOutlined key="3" />);
  }

  if (item.imported) {
    icons.push(<UploadOutlined key="4" />);
  }
  return icons;
};

const Description = styled.div`
  font-size: 12px;
  color: #7a7a7a;
  margin-bottom: 10px;
`;

const FilterSetFooter = styled.div`
  display: flex;
  flex: 1;
  justify-content: space-between;
`;
const FilterSetList = ({ item, info, loadFilterSets, deleteFilterSet, noRights }) => (
  <Card
    size="small"
    bordered={false}
    title={
      <>
        {getIcons(item)} {item.name}
      </>
    }
    headStyle={{ background: '#efefef' }}
    extra={
      <>
        {!noRights && deleteFilterSet && (
          <Tooltip title="Delete" getPopupContainer={() => document.getElementById('container')}>
            <Button size="small" type="danger" icon={<DeleteOutlined />} onClick={() => deleteFilterSet('global', item)} />
          </Tooltip>
        )}
      </>
    }
  >
    <div id="container" />
    <Description>{item.description}</Description>
    <FilterSetFooter>
      <Space>
        <Tooltip title="Load" getPopupContainer={() => document.getElementById('container')}>
          <Button size="small" type="primary" icon={<CaretRightOutlined />} onClick={() => loadFilterSets(item)} />
        </Tooltip>
      </Space>
      <Space split="|">
        <span>{`${item.pageTitle} Page`}</span>
        <span>Shared</span>
        {!info && <InfoCircleOutlined />}
      </Space>
    </FilterSetFooter>
  </Card>
);

FilterSetList.propTypes = {
  item: PropTypes.object.isRequired,
  loadFilterSets: PropTypes.func.isRequired,
  deleteFilterSet: PropTypes.func,
  info: PropTypes.bool,
  noRights: PropTypes.bool,
};

export default FilterSetList;
