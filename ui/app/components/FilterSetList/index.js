import React from 'react';
import { Menu, Dropdown, Space, Card } from 'antd';
import {
  BellOutlined,
  DashboardOutlined,
  IdcardOutlined,
  SafetyOutlined,
  UploadOutlined,
  MenuOutlined,
  InfoCircleOutlined,
  DeleteOutlined,
  ImportOutlined,
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
      <Dropdown
        getPopupContainer={() => document.getElementById('container')}
        overlay={
          <Menu>
            <Menu.Item icon={<ImportOutlined />} onClick={() => loadFilterSets(item)}>
              Load
            </Menu.Item>
            {!noRights && deleteFilterSet && (
              <Menu.Item icon={<DeleteOutlined />} key="delete" onClick={() => deleteFilterSet('global', item)}>
                Delete
              </Menu.Item>
            )}
          </Menu>
        }
        trigger={['hover']}
      >
        <div id="container">
          <MenuOutlined />
        </div>
      </Dropdown>
    }
  >
    <Description>{item.description}</Description>
    <Space split="|">
      <span>{`${item.pageTitle} Page`}</span>
      <span>Shared</span>
      {!info && <InfoCircleOutlined />}
    </Space>
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
