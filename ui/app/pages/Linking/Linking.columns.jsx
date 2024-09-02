import React from 'react';

import { CreateModal } from './CreateModal';
import { DeleteModal } from './DeleteModal';
import * as Style from './Linking.style';

export const getColumns = refetch => [
  {
    title: 'Name',
    dataIndex: 'name',
  },
  {
    title: 'Entities',
    dataIndex: 'entities',
    render: (value, record) => (record.all ? 'All' : value?.map(entity => entity.name).join(', ')),
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
          <CreateModal initialValues={formattedRecord} onSuccess={refetch} />
          <DeleteModal pk={record.pk} onSuccess={refetch} />
        </Style.TableActions>
      );
    },
  },
];
