import React, { useState } from 'react';

import { Col, Row, Table } from 'antd';

import UIBreadcrumb from 'ui/components/UIElements/UIBreadcrumb';
import { buildListUrlParams } from 'ui/helpers/common';
import { Link } from 'ui/helpers/Link';
import useAutorun from 'ui/helpers/useAutorun';
import { useStore } from 'ui/mobx/RootStoreProvider';
import API from 'ui/services/API';

import { CreateModal } from './CreateModal/CreateModal';
import { getColumns } from './Linking.columns';

const Linking = () => {
  const { commonStore } = useStore();
  const [deeplinks, setDeeplinks] = useState(null);
  const [conf, setConf] = useState({
    pagination: {
      page: 1,
      perPage: 10,
      perPageOptions: [10, 20, 50, 100],
    },
    sort: { id: 'name', asc: true },
  });
  const [count, setCount] = useState(null);

  const fetchDeeplinks = async () => {
    const params = buildListUrlParams(conf);
    const response = await API.fetchDeeplinks(params);
    if (response.ok) {
      setDeeplinks(response.data?.results);
      setCount(response.data?.count || 0);
    }
    // If the page is not valid, we try to go to the previous one
    // This is a workaround for when deleting the only item of a page
    if (response.data.detail === 'Invalid page.' && conf.pagination.page > 1) {
      setConf({ ...conf, pagination: { ...conf.pagination, page: conf.pagination.page - 1 } });
    }
  };

  useAutorun(fetchDeeplinks, [conf, 'tenant']);

  const handleSuccess = async () => {
    await fetchDeeplinks();
    commonStore.fetchLinkTemplates();
  };

  return (
    <div>
      <UIBreadcrumb
        items={[
          'Administration',
          <Link app to="administration/external-links">
            External links
          </Link>,
        ]}
      />
      <Col span={24}>
        <h1>External links templates</h1>
        <p>Create templates in order to add links in the contextual menu when right clicking on different values</p>
      </Col>
      <Row style={{ marginTop: '1.5rem', marginBottom: '1rem' }}>
        <CreateModal onSuccess={handleSuccess} />
      </Row>
      <Table
        dataSource={deeplinks}
        columns={getColumns(handleSuccess)}
        pagination={{
          current: conf.pagination.page,
          pageSize: conf.pagination.perPage,
          onChange: (page, perPage) => setConf({ ...conf, pagination: { ...conf.pagination, page, perPage } }),
          perPageOptions: conf.pagination.perPageOptions,
          total: count,
        }}
      />
    </div>
  );
};
Linking.metadata = {
  category: 'ADMINISTRATION',
  url: 'administration/external-links',
  position: 0,
  title: 'External links',
};

export default Linking;
