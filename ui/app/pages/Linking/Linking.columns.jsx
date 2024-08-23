import React from 'react';

import { DeleteModal } from './DeleteModal';
import { EditModal } from './EditModal';
import * as Style from './Linking.style';

export const columns = [
  {
    title: 'Entity',
    dataIndex: 'entity',
  },
  {
    title: 'Template',
    dataIndex: 'template',
  },
  {
    title: 'Actions',
    dataIndex: 'actions',
    render: (text, record) => (
      <Style.TableActions>
        <EditModal initialValues={record} />
        <DeleteModal />
      </Style.TableActions>
    ),
  },
];
