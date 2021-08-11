/**
 *
 * HelpMenu
 *
 */

import React from 'react';
import { Button } from 'antd';
import styled from 'styled-components';
import GlyphIcon from 'ui/components/GlyphIcon';

const Wrapper = styled.div`
  display: flex;
  flex-direction: column;
  width: 160px;
`;

const Item = styled(Button)`
  text-align: left !important;
  padding-left: 5px !important;
  span {
    padding-left: 10px;
  }
  &:hover {
    background-color: #f0f0f0 !important;
  }
`;

const UserMenu = () => (
  <Wrapper>
    <Item
      block
      type="link"
      icon={<GlyphIcon type="cog" />}
      onClick={() => {
        window.location = '/accounts/edit';
      }}
    >
      Account settings
    </Item>
    <Item
      block
      type="link"
      icon={<GlyphIcon type="log-out" />}
      onClick={() => {
        window.location = '/accounts/logout';
      }}
    >
      Logout
    </Item>
  </Wrapper>
);

UserMenu.propTypes = {};

export default UserMenu;
