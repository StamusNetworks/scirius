import React, { useState } from 'react';

import { Col, Row, Table } from 'antd';

import UIBreadcrumb from 'ui/components/UIElements/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';
import useAutorun from 'ui/helpers/useAutorun';
import { useStore } from 'ui/mobx/RootStoreProvider';
import API from 'ui/services/API';

import { CreateModal } from './CreateModal/CreateModal';
import { columns } from './Linking.columns';

const dummyData = [
  {
    pk: 1,
    label: 'Google',
    entities: ['Threat'],
    template: 'https://www.google.com/search?q={{ value }}',
  },
];

const Linking = () => {
  const { commonStore } = useStore();
  const [deeplinks, setDeeplinks] = useState(null);

  const fetchDeeplinks = async () => {
    const response = await API.fetchDeeplinks();
    if (response.ok) {
      setDeeplinks(response.data?.results);
    }
  };

  useAutorun(fetchDeeplinks, ['tenant']);

  const handleSuccess = async () => {
    await fetchDeeplinks();
    commonStore.fetchLinkTemplates();
  };

  return (
    <div>
      <UIBreadcrumb
        items={[
          'Administration',
          <Link app to="administration/linking">
            Linking
          </Link>,
        ]}
      />
      <Col span={24}>
        <h1>Contextual DeepLinking</h1>
        <p>Create templates in order to add links in the contextual menu when right clicking on different values</p>
      </Col>
      <Row style={{ marginTop: '1.5rem', marginBottom: '1rem' }}>
        <CreateModal onSuccess={handleSuccess} />
      </Row>
      <Table dataSource={deeplinks} columns={columns} />
    </div>
  );
};
Linking.metadata = {
  category: 'ADMINISTRATION',
  url: 'administration/linking',
  position: 0,
};

export default Linking;
