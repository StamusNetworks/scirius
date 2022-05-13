import React from 'react';
import { Dropdown, Menu, Space } from 'antd';
import { DownOutlined } from '@ant-design/icons';
import PropTypes from 'prop-types';

const ActionsButtons = ({ supportedActions }) => {
  if (process.env.REACT_APP_HAS_ACTION === '1' || process.env.NODE_ENV === 'development') {
    if (supportedActions.length === 0) {
      return (
        <Dropdown id="dropdown-basic-actions" overlay={null} disabled>
          <Space>
            Policy Actions
          </Space>
        </Dropdown>
      );
    }
    const actions = [];
    for (let i = 0; i < supportedActions.length; i += 1) {
      const action = supportedActions[i];
      if (action[0] === '-') {
        actions.push(<Menu.Divider />);
      } else {
        actions.push(
          <Menu.Item key={action[0]} onClick={() => { /* this.createAction(action[0]); */ }}>{action[1]}</Menu.Item>
        );
      }
    }
    return (
      <Dropdown id="dropdown-basic-actions" overlay={<Menu>{actions}</Menu>} trigger={['hover']}>
        <Space>
          <a href='#'>Policy Actions <DownOutlined /></a>
        </Space>
      </Dropdown>
    );
  }
  return null;
}

ActionsButtons.propTypes = {
  supportedActions: PropTypes.array.isRequired
}

export default ActionsButtons;
