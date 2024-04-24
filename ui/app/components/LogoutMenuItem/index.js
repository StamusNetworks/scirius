import React from 'react';

import { PoweroffOutlined } from '@ant-design/icons';

import * as Styled from 'ui/components/UserMenu/style';

const LogoutMenuItem = () => (
  <Styled.Item
    block
    type="link"
    icon={<PoweroffOutlined />}
    onClick={() => {
      window.location = '/accounts/logout';
    }}
    data-test="logout-button"
  >
    Log Out
  </Styled.Item>
);

export default LogoutMenuItem;
