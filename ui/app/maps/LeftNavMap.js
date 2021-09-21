import React from 'react';
import { ImageSearchOutlined, SettingsOutlined } from "@material-ui/icons";


export const LeftNavMap = {
    HUNTING: {
        title: 'Hunting',
        icon: () => <ImageSearchOutlined style={{ color: "currentColor", strokeWidth: 1.5 }} />,
    },
    MANAGEMENT: {
        title: 'Management',
        icon: () => <SettingsOutlined style={{ color: "currentColor", strokeWidth: 1.5 }} />,
    },
};
