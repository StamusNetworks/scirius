import React from 'react';

import { Button, Col, Row, Table } from 'antd';

import UIBreadcrumb from 'ui/components/UIElements/UIBreadcrumb';
import { Link } from 'ui/helpers/Link';

import { columns } from './Linking.columns';
import { CreateModal } from './CreateModal/CreateModal';

const dummyData = [
  {
    pk: 1,
    entity: 'Threat',
    template: 'https://www.google.com/search?q={{ value }}',
  },
];

const Linking = () => (
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
      <CreateModal />
    </Row>
    <Table dataSource={dummyData} columns={columns} />
  </div>
);
Linking.metadata = {
  category: 'ADMINISTRATION',
  url: 'administration/linking',
  position: 0,
};

export default Linking;
