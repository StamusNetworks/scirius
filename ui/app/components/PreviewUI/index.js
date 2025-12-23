import React from 'react';

import { PlayCircleOutlined } from '@ant-design/icons';
import { Menu } from 'antd';
import styled from 'styled-components';

const Link = styled.a`
  display: flex;
  align-items: center;
  padding: 0 1rem;
`;

const Icon = styled.span`
  margin-right: 0.5rem;
  display: inline-flex;
  svg {
    width: 1.5rem;
    height: 1.5rem;
  }
`;

export default () => (
  <Menu.Item key="preview">
    <Link href="/preview" target="_blank" rel="noopener noreferrer">
      <Icon>
        <PlayCircleOutlined />
      </Icon>
      Preview new UI
    </Link>
  </Menu.Item>
);
