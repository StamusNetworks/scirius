import React from 'react';

import { CreateModal } from './CreateModal';
import { DeleteModal } from './DeleteModal';
import * as Style from './Linking.style';
import { ToggleEnabled } from './ToggleEnabled/ToggleEnabled';

export const getColumns = refetch => [
  {
    title: 'Enabled',
    dataIndex: 'enabled',
    render: (value, record) => <ToggleEnabled pk={record.pk} onSuccess={refetch} enabled={value} />,
  },
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
          <CreateModal initialValues={formattedRecord} onSuccess={refetch} disabled={!record.user_defined} />
          <DeleteModal pk={record.pk} onSuccess={refetch} disabled={!record.user_defined} />
        </Style.TableActions>
      );
    },
  },
];
