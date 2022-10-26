import React from 'react';
import { Space, Card, Tooltip, Button } from 'antd';
import {
  BellOutlined,
  DashboardOutlined,
  IdcardOutlined,
  SafetyOutlined,
  UploadOutlined,
  DeleteOutlined,
} from '@ant-design/icons';
import PropTypes from 'prop-types';
import styled from 'styled-components';
import { huntTabs } from 'ui/constants';

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

const Container = styled.div`
  cursor: pointer;
  margin: -10px;
  padding: 10px;
  &:hover {
    background-color: #f6f6f6;
    text-shadow: 0 1px #ffffff;
  }
`;

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
    <Container onClick={() => loadFilterSets(item)}>
      {item.description && <Description>{item.description}</Description>}
      <FilterSetFooter>
        <Space split="|">
          <span>{`${huntTabs[item.page]} Page`}</span>
          <span>Shared</span>
        </Space>
      </FilterSetFooter>
    </Container>
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
