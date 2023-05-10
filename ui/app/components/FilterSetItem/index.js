import React from 'react';
import { Card, Tooltip, Button } from 'antd';
import { BellOutlined, DashboardOutlined, IdcardOutlined, SafetyOutlined, UploadOutlined, DeleteOutlined, LoadingOutlined } from '@ant-design/icons';
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
const FilterSetItem = ({ item, loadFilterSets, onDelete, hasRights, loading, type }) => (
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
      // we always show delete icon for private filtersets
      (type === 'private' || hasRights) &&
      onDelete && (
        <Tooltip title="Delete" getPopupContainer={() => document.getElementById('container')}>
          <Button
            size="small"
            type="danger"
            icon={loading ? <LoadingOutlined /> : <DeleteOutlined />}
            onClick={() => onDelete()}
            data-test="filter-set-delete"
          />
        </Tooltip>
      )
    }
    data-test={`filter-set-${item.name}`}
  >
    <Container onClick={() => loadFilterSets(item)} data-test={`filter-set-item-${item.name}`}>
      {item.description && <Description>{item.description}</Description>}
      <FilterSetFooter data-test={`${huntTabs[item.page]} Page`}>{`${huntTabs[item.page]} Page`}</FilterSetFooter>
    </Container>
  </Card>
);

FilterSetItem.propTypes = {
  loading: PropTypes.bool.isRequired,
  item: PropTypes.object.isRequired,
  loadFilterSets: PropTypes.func.isRequired,
  onDelete: PropTypes.func,
  hasRights: PropTypes.bool,
  type: PropTypes.string,
};

export default FilterSetItem;
