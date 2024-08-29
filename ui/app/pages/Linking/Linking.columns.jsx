import React from 'react';

import { DeleteModal } from './DeleteModal';
import { EditModal } from './EditModal';
import * as Style from './Linking.style';

export const columns = [
  {
    title: 'Name',
    dataIndex: 'name',
  },
  {
    title: 'Entities',
    dataIndex: 'entities',
    render: value => value?.map(entity => entity.name).join(', '),
  },
  {
    title: 'Template',
    dataIndex: 'template',
  },
  {
    title: 'Actions',
    dataIndex: 'actions',
    render: (_, record) => {
      const formattedRecord = { ...record, entities: record.entities.map(entity => entity.name) };
      return (
        <Style.TableActions>
          <EditModal initialValues={formattedRecord} />
          <DeleteModal />
        </Style.TableActions>
      );
    },
  },
];
