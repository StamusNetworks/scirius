import React from 'react';
import { ImageSearchOutlined, SettingsOutlined, LinkOutlined } from '@material-ui/icons';

export const LeftNavMap = [
  {
    id: 'STAMUS_ND',
    title: 'Hunting',
    icon: () => <ImageSearchOutlined style={{ color: 'currentColor', strokeWidth: 1.5 }} />,
  },
  {
    id: 'ADMINISTRATION',
    title: 'Administration',
    icon: () => <SettingsOutlined style={{ color: 'currentColor', strokeWidth: 1.5 }} />,
  },
  {
    id: 'OTHER_APPS',
    title: 'Other Apps',
    icon: () => <LinkOutlined style={{ color: 'currentColor', strokeWidth: 1.5 }} />,
  },
];
