import React from 'react';

import { SettingOutlined } from '@ant-design/icons';

import LogoutMenuItem from 'ui/components/LogoutMenuItem';

import * as Style from './style';

const UserMenu = () => (
  <Style.Wrapper>
    <Style.Item
      block
      type="link"
      icon={<SettingOutlined />}
      onClick={() => {
        window.location = '/accounts/edit';
      }}
    >
      Account Settings
    </Style.Item>
    <LogoutMenuItem />
  </Style.Wrapper>
);

UserMenu.propTypes = {};

export default UserMenu;
