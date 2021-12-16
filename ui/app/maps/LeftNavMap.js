import React from 'react';
import { ImageSearchOutlined, SettingsOutlined } from "@material-ui/icons";


export const LeftNavMap = [
  {
    id: 'STAMUS_ND',
    title: 'Stamus ND',
    icon: () => <ImageSearchOutlined style={{ color: "currentColor", strokeWidth: 1.5 }} />,
  },
  {
    id: 'OTHER_APPS',
    title: 'Other Apps',
    icon: () => <SettingsOutlined style={{ color: "currentColor", strokeWidth: 1.5 }} />,
  },
];
