import React from 'react';

import { DeleteModal } from './DeleteModal';
import { EditModal } from './EditModal';
import * as Style from './Linking.style';

export const columns = [
  {
    title: 'Label',
    dataIndex: 'label',
  },
  {
    title: 'Entities',
    dataIndex: 'entities',
    render: value => value?.join(', '),
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
