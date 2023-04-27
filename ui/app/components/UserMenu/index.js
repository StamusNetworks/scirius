import React from 'react';
import { Button } from 'antd';
import styled from 'styled-components';
import { PoweroffOutlined, SettingOutlined } from '@ant-design/icons';

const Wrapper = styled.div`
  display: grid;
  grid-gap: 10px;
  width: 240px;
`;

const Item = styled(Button)`
  display: grid;
  grid-template-columns: min-content 1fr;
  align-items: center;
  padding: 0;
  border: none;

  &:hover {
    background: #f0f2f5;
  }
  &:active {
    background: #bcccd1;
  }
  &:hover svg {
    color: rgba(0, 0, 0, 0.85);
  }

  & > span {
    display: flex;
    padding: 5px 8px;
    margin: 0px !important;
    color: rgba(0, 0, 0, 0.85);
  }

  & svg {
    height: 22px;
    width: 22px;
    color: #d9d9d9;
    transition: all 0.6s;
  }
`;

const UserMenu = () => (
  <Wrapper>
    <Item
      block
      type="link"
      icon={<SettingOutlined />}
      onClick={() => {
        window.location = '/accounts/edit';
      }}
    >
      Account Settings
    </Item>
    <Item
      block
      type="link"
      icon={<PoweroffOutlined />}
      onClick={() => {
        window.location = '/accounts/logout';
      }}
      data-test="logout-button"
    >
      Log Out
    </Item>
  </Wrapper>
);

UserMenu.propTypes = {};

export default UserMenu;
