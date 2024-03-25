import React from 'react';

import { AlertOutlined, CalendarOutlined, FieldBinaryOutlined, MessageOutlined, UserOutlined } from '@ant-design/icons';

const options = [
  {
    icon: <CalendarOutlined />,
    id: 'date',
    title: 'Date',
    isNumeric: true,
    defaultAsc: false,
    page: 'HISTORY',
  },
  {
    icon: <UserOutlined />,
    id: 'username',
    title: 'User',
    isNumeric: false,
    defaultAsc: false,
    page: 'HISTORY',
  },
  {
    icon: <FieldBinaryOutlined />,
    id: 'client_ip',
    title: 'Client IP',
    isNumeric: false,
    defaultAsc: false,
    page: 'HISTORY',
  },
  {
    icon: <CalendarOutlined />,
    id: 'created',
    title: 'Created',
    isNumeric: true,
    defaultAsc: false,
    page: 'RULES_LIST',
  },
  {
    icon: <AlertOutlined />,
    id: 'hits',
    title: 'Alerts',
    isNumeric: true,
    defaultAsc: false,
    page: 'RULES_LIST',
  },
  {
    icon: <MessageOutlined />,
    id: 'msg',
    title: 'Message',
    isNumeric: false,
    defaultAsc: true,
    page: 'RULES_LIST',
  },
  {
    icon: <CalendarOutlined />,
    id: 'updated',
    title: 'Updated',
    isNumeric: true,
    defaultAsc: false,
    page: 'RULES_LIST',
  },
];

export default options;
