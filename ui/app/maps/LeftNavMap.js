import React from 'react';

import { LinkOutlined, SecurityScanOutlined, SettingOutlined } from '@ant-design/icons';

export const LeftNavMap = [
  {
    id: 'STAMUS_ND',
    title: 'Hunting',
    icon: () => <SecurityScanOutlined />,
  },
  {
    id: 'ADMINISTRATION',
    title: 'Administration',
    icon: () => <SettingOutlined />,
  },
  {
    id: 'OTHER_APPS',
    title: 'Other Apps',
    icon: () => <LinkOutlined style={{ transform: 'rotate(45deg)' }} />,
  },
];
