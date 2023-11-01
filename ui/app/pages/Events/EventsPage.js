/*
Copyright(C) 2018 Stamus Networks
Written by Eric Leblond <eleblond@stamus-networks.com>

This file is part of Scirius.

Scirius is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Scirius is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Scirius.  If not, see <http://www.gnu.org/licenses/>.
*/

import React, { useState } from 'react';
import { Table } from 'antd';
import { BellFilled } from '@ant-design/icons';
import { Helmet } from 'react-helmet';
import { observer } from 'mobx-react-lite';
import { STAMUS } from 'ui/config';
import ErrorHandler from 'ui/components/Error';
import HuntRestError from 'ui/components/HuntRestError';
import Filters from 'ui/components/Filters';
import moment from 'moment';
import buildListParams from 'ui/helpers/buildListParams';
import { useStore } from 'ui/mobx/RootStoreProvider';
import useAutorun from 'ui/helpers/useAutorun';
import useFilterParams from 'ui/hooks/useFilterParams';
import { buildListUrlParams } from '../../helpers/common';
import AlertItem from './components/AlertItem';
import HuntPaginationRow from '../../HuntPaginationRow';

const EventsPage = () => {
  const { commonStore, esStore } = useStore();
  const filterParams = useFilterParams();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [errors, setErrors] = useState(null);
  const [count, setCount] = useState(0);
  const [alertsList, setAlertList] = useState(
    buildListParams(JSON.parse(localStorage.getItem('alerts_list')), {
      pagination: {
        page: 1,
        perPage: 10,
        perPageOptions: [10, 20, 50, 100],
      },
      sort: { id: 'timestamp', asc: false },
    }),
  );

  const updateRuleListState = rulesListState => {
    setAlertList(rulesListState);
    localStorage.setItem('alerts_list', JSON.stringify(rulesListState));
  };

  const paginationParams = buildListUrlParams(alertsList);

  const fetchData = async () => {
    try {
      setLoading(true);
      const data = await esStore.fetchAlertsTail(paginationParams);
      setAlerts(data?.results || []);
      setCount(data?.count || 0);
      setLoading(false);
    } catch (error) {
      if (error.response.status === 500) {
        setErrors([`${error.response.data[0].slice(0, 160)}...`]);
        setLoading(false);
        return;
      }
      setErrors([]);
      setLoading(false);
    }
  };

  useAutorun(fetchData, [paginationParams, JSON.stringify(commonStore.eventTypes)]);

  const getIconColor = key => {
    if (key === 'informational') return '#7b1244';
    if (key === 'relevant') return '#ec7a08';
    return '#005792';
  };

  const columns = [
    {
      title: '',
      render: (e, row) => (
        <div>
          <BellFilled style={{ color: getIconColor(row.tag) }} />
        </div>
      ),
    },
    {
      title: 'Timestamp',
      dataIndex: 'timestamp',
      onHeaderCell: () => ({
        'data-test': 'timestamp',
      }),
    },
    {
      title: 'Method',
      dataIndex: 'method',
      onHeaderCell: () => ({
        'data-test': 'method',
      }),
    },
    {
      title: 'Source IP',
      dataIndex: 'source_ip',
      onHeaderCell: () => ({
        'data-test': 'source-ip',
      }),
    },
    {
      title: 'Destination IP',
      dataIndex: 'destination_ip',
      onHeaderCell: () => ({
        'data-test': 'destination-ip',
      }),
    },
    {
      title: 'Proto',
      dataIndex: 'proto',
      onHeaderCell: () => ({
        'data-test': 'proto',
      }),
    },
    {
      title: 'Probe',
      dataIndex: 'probe',
      onHeaderCell: () => ({
        'data-test': 'probe',
      }),
    },
    {
      title: 'Category',
      dataIndex: 'category',
      onHeaderCell: () => ({
        'data-test': 'category',
      }),
    },
    {
      title: 'Tag',
      dataIndex: 'tag',
      onHeaderCell: () => ({
        'data-test': 'tag',
      }),
    },
  ];

  const dataSource = alerts.map(rule => ({
    key: rule._id,
    timestamp: moment(rule.timestamp).format('YYYY-MM-DD, hh:mm:ss a'),
    method: rule.alert.signature,
    source_ip: rule.src_ip,
    destination_ip: rule.dest_ip,
    proto: rule.app_proto || rule.proto,
    probe: rule.host,
    category: rule.alert.category,
    tag: rule.alert.tag || 'untagged',
    rule, // we need this to access the rule data in the `expandedRowRender` below
  }));

  return (
    <div>
      <Helmet>
        <title>{`${STAMUS} - Events`}</title>
      </Helmet>

      {errors && <HuntRestError errors={errors} />}
      <ErrorHandler>
        <Filters page="ALERTS_LIST" filterTypes={['HOST', 'EVENT']} />
      </ErrorHandler>

      <Table
        data-test="alerts-table"
        size="small"
        loading={loading}
        dataSource={dataSource}
        columns={columns}
        expandable={{
          columnWidth: 5,
          expandRowByClick: true,
          expandedRowRender: alert => <AlertItem data={alert.rule} filterParams={filterParams} />,
          rowExpandable: () => true,
        }}
        pagination={false}
        onRow={(r, index) => ({
          'data-test': `table-row-${index}`,
        })}
      />

      <ErrorHandler>
        <HuntPaginationRow viewType="list" onPaginationChange={updateRuleListState} itemsCount={count} itemsList={alertsList} />
      </ErrorHandler>
    </div>
  );
};

export default observer(EventsPage);
